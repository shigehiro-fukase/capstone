#include <stdio.h>
#include <stdlib.h>

#include <capstone/platform.h>
#include <capstone/capstone.h>

struct platform {
	cs_arch arch;
	cs_mode mode;
	unsigned char *code;
	size_t size;
	const char *comment;
};

static csh handle;

static void print_string_hex(const char *comment, unsigned char *str, size_t len)
{
	unsigned char *c;

	printf("%s", comment);
	for (c = str; c < str + len; c++) {
		printf("0x%02x ", *c & 0xff);
	}

	printf("\n");
}

static char * snprint_bits(char* dst, uint32_t num, unsigned bits) {
	int i;
	uint32_t b;
	char *p = dst;
	for (i=bits-1; i>=0; i--) {
		b = (num >> i) & 1;
		*p = '0' + b;
		p++;
	}
	return p;
}
static void print_insn_bits(cs_insn *ins) {
	char buf[64];
	buf[0] = '\0';
	if (ins->size == 2) {
		uint16_t num = *((uint16_t*) ins->bytes);
		char *p = buf;
		p = snprint_bits(p, (num>>13) & 7, 3);
		*p++ = '|';
		p = snprint_bits(p, (num>>2) & 0x7FF, 11);
		*p++ = '|';
		p = snprint_bits(p, (num>>0) & 0x3, 2);
		*p++ = '\0';
	} else if (ins->size == 4) {
		uint32_t num = *((uint32_t*) ins->bytes);
		char *p = buf;
		p = snprint_bits(p, (num>>15), 17);
		*p++ = '|';
		p = snprint_bits(p, (num>>12) & 7, 3);
		*p++ = '|';
		p = snprint_bits(p, (num>> 7) & 0x1F, 5);
		*p++ = '|';
		p = snprint_bits(p, (num>> 2) & 0x1F, 5);
		*p++ = '|';
		p = snprint_bits(p, (num>> 0) & 0x3, 2);
		*p++ = '\0';
	}
	printf("%s", buf);
}
static void print_insn_bytes(cs_insn *ins) {
	int i;
	for (i=0; i<ins->size; i++) {
		printf("%s%02X", (i==0) ? "" : " ", ins->bytes[i]);
	}
}
static void print_insn_detail(cs_insn *ins)
{
	int i;
	int n;
	cs_riscv *riscv;
	cs_detail *detail;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	riscv = &(ins->detail->riscv);
	detail = ins->detail;
	if (riscv->op_count)
		printf("op(%u) ", riscv->op_count);

	for (i = 0; i < riscv->op_count; i++) {
		cs_riscv_op *op = &(riscv->operands[i]);
		switch((int)op->type) {
			default:
				printf("error in opt_type:%u", (int)op->type);
				break;
			case RISCV_OP_REG:
				printf("[%u]{.type:REG=%s}", i, cs_reg_name(handle, op->reg));
				break;
			case RISCV_OP_IMM:
				printf("[%u]{.type:IMM=0x%" PRIx64 "}", i, op->imm);
				break;
			case RISCV_OP_MEM:
				printf("[%u]{.type:MEM}", i);
				if (op->mem.base != RISCV_REG_INVALID)
					printf("[%u]{.mem.base: REG=%s}",
							i, cs_reg_name(handle, op->mem.base));
				if (op->mem.disp != 0)
					printf("[%u]{.mem.disp:0x%" PRIx64 "}", i, op->mem.disp);

				break;
		}
	}
	
	//print the groups this instruction belongs to
	if (detail->groups_count > 0) {
		printf(" groups[");
		for (n = 0; n < detail->groups_count; n++) {
			printf("%s ", cs_group_name(handle, detail->groups[n]));
		}
		printf("]");
	}

}

static void test()
{
#define RISCV_CODE32 "\x37\x34\x00\x00\x97\x82\x00\x00\xef\x00\x80\x00\xef\xf0\x1f\xff\xe7\x00\x45\x00\xe7\x00\xc0\xff\x63\x05\x41\x00\xe3\x9d\x61\xfe\x63\xca\x93\x00\x63\x53\xb5\x00\x63\x65\xd6\x00\x63\x76\xf7\x00\x03\x88\x18\x00\x03\x99\x49\x00\x03\xaa\x6a\x00\x03\xcb\x2b\x01\x03\xdc\x8c\x01\x23\x86\xad\x03\x23\x9a\xce\x03\x23\x8f\xef\x01\x93\x00\xe0\x00\x13\xa1\x01\x01\x13\xb2\x02\x7d\x13\xc3\x03\xdd\x13\xe4\xc4\x12\x13\xf5\x85\x0c\x13\x96\xe6\x01\x13\xd7\x97\x01\x13\xd8\xf8\x40\x33\x89\x49\x01\xb3\x0a\x7b\x41\x33\xac\xac\x01\xb3\x3d\xde\x01\x33\xd2\x62\x40\xb3\x43\x94\x00\x33\xe5\xc5\x00\xb3\x76\xf7\x00\xb3\x54\x39\x01\xb3\x50\x31\x00\x33\x9f\x0f\x00"
#define RISCV_CODE64 "\x13\x04\xa8\x7a"  // aaa80413
	struct platform platforms[] = {
		{
			CS_ARCH_RISCV,
			CS_MODE_RISCV32,
			(unsigned char *)RISCV_CODE32,
			sizeof(RISCV_CODE32) - 1,
			"riscv32"
		},
		{
			CS_ARCH_RISCV,
			CS_MODE_RISCV64,
			(unsigned char *)RISCV_CODE64,
			sizeof(RISCV_CODE64) - 1,
			"riscv64"
		}
	};
	
	uint64_t address = 0x1000;
	cs_insn *insn;
	int i;
	size_t count;

	for (i = 0; i < sizeof(platforms)/sizeof(platforms[0]); i++) {
		cs_err err = cs_open(platforms[i].arch, platforms[i].mode, &handle);
		if (err) {
			printf("Failed on cs_open() with error returned: %u\n", err);
			continue;
		}
		
		//To turn on or off the Print Details option
		//cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF); 
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

		count = cs_disasm(handle, platforms[i].code, platforms[i].size, address, 0, &insn);
		if (count) {
			size_t j;

			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code:", platforms[i].code, platforms[i].size);
			printf("Disasm:\n");

			for (j = 0; j < count; j++) {
				// address
				printf("0x%" PRIx64 ": ", insn[j].address);
				// bits
				print_insn_bits(&insn[j]);
				printf("  ");
				// bytes
				print_insn_bytes(&insn[j]);
				printf("  ");
				// mnemonic op
				char mnbuf[64];
				sprintf(mnbuf, "%-6s %s", insn[j].mnemonic, insn[j].op_str);
				printf("%-24s  ", mnbuf);
				print_insn_detail(&insn[j]);
				printf("\n");
			}
			printf("0x%" PRIx64 ":\n", insn[j-1].address + insn[j-1].size);

			// free memory allocated by cs_disasm()
			cs_free(insn, count);
		} else {
			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code:", platforms[i].code, platforms[i].size);
			printf("ERROR: Failed to disasm given code!\n");
		}

		printf("\n");

		cs_close(&handle);
	}
}

int main()
{
	test();

	return 0;
}
