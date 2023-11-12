#include <stdio.h>
#include <stdlib.h>

#include <capstone/platform.h>
#include <capstone/capstone.h>

static uint64_t opt_offset = 0;
static unsigned long opt_XLEN = 64;
static int usage(int argc, char * argv[]);
static int bad_arg(int argc, char * argv[], int n1, int n2);

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
        strcpy(p, "                  ");
		p = p+strlen(p);
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
	if (ins->size == 2) {
		for (i=0; i<ins->size; i++) {
			printf("%s%02X", (i==0) ? "" : " ", ins->bytes[i]);
		}
        printf("      ");
	} else if (ins->size == 4) {
		for (i=0; i<ins->size; i++) {
			printf("%s%02X", (i==0) ? "" : " ", ins->bytes[i]);
		}
	} else {
		for (i=0; i<ins->size; i++) {
			printf("%s%02X", (i==0) ? "" : " ", ins->bytes[i]);
		}
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
		printf("%sgroups[", (riscv->op_count) ? " " : "");
		for (n = 0; n < detail->groups_count; n++) {
			printf("%s%s", (n==0) ? "" : " ", cs_group_name(handle, detail->groups[n]));
		}
		printf("]");
	}

}

#define SHOW_PLATFORM	(1<<0)
#define SHOW_CODE		(1<<1)
#define SHOW_DISASM		(1<<2)
static void disasm(struct platform * platform, uint64_t address, uint64_t offset, int flags) {
	cs_insn *insn;
	size_t count;

	if (flags == 0) flags = SHOW_PLATFORM | SHOW_DISASM;

	cs_err err = cs_open(platform->arch, platform->mode, &handle);
	if (err) {
		printf("Failed on cs_open() with error returned: %u\n", err);
		return;
	}

	//To turn on or off the Print Details option
	//cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF); 
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	count = cs_disasm(handle, platform->code, platform->size, address, 0, &insn);
	if (count) {
		size_t j;

		printf("****************\n");
		if (flags & SHOW_PLATFORM) printf("Platform: %s\n", platform->comment);
		if (flags & SHOW_CODE) print_string_hex("Code:", platform->code, platform->size);
		if (flags & SHOW_DISASM) printf("Disasm:\n");

		for (j = 0; j < count; j++) {
			// address
			printf("0x%08" PRIx64 ": ", insn[j].address);
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
		printf("0x%08" PRIx64 ": END\n", insn[j-1].address + insn[j-1].size);

		// free memory allocated by cs_disasm()
		cs_free(insn, count);
	} else {
		printf("****************\n");
		if (flags & SHOW_PLATFORM) printf("Platform: %s\n", platform->comment);
		if (flags & SHOW_CODE) print_string_hex("Code:", platform->code, platform->size);
		if (flags & SHOW_DISASM) printf("ERROR: Failed to disasm given code!\n");
	}

	printf("\n");

	cs_close(&handle);
}
static void test() {
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
	int i;

	for (i = 0; i < sizeof(platforms)/sizeof(platforms[0]); i++) {
		disasm(&platforms[i], 0x1000, 0, 0);
	}
}
static int test1() {
	int ret = 0;
	const char * ifnames[] = {
		"E:/riscv/riscv-test/tool/test1/make-execlang-riscv32-unknown-elf/test1.bin",
		"E:/riscv/riscv-test/tool/test1/make-execlang-riscv64-unknown-elf/test1.bin",
		"E:/riscv/riscv-test/tool/test1/make-gcc-riscv64-unknown-elf/test1.bin",
	};
	struct platform platforms[] = {
		{
			CS_ARCH_RISCV,
			CS_MODE_RISCV32|CS_MODE_RISCVC,
			(unsigned char *)NULL,
			0,
			"riscv32"
		},
		{
			CS_ARCH_RISCV,
			CS_MODE_RISCV64|CS_MODE_RISCVC,
			(unsigned char *)NULL,
			0,
			"riscv64"
		},
		{
			CS_ARCH_RISCV,
			CS_MODE_RISCV64|CS_MODE_RISCVC,
			(unsigned char *)NULL,
			0,
			"riscv64"
		}
	};
	int i;
	for (i = 0; i < sizeof(ifnames)/sizeof(ifnames[0]); i++) {
		FILE *ifp;
		fpos_t fpos; 
		printf("ifnames=\"%s\"\n", ifnames[i]);
		ifp = fopen(ifnames[i], "rb");
		if (!ifp) {
			printf("Cannot open file \"%s\"\n", ifnames[i]);
			return -1;
		}

		fseek(ifp, 0, SEEK_END); 
		fgetpos(ifp, &fpos); 
		fseek(ifp, 0, SEEK_SET); 

		if (fpos == 0) {
			printf("Empty file.\n");
			ret = -1;
			goto L_RETURN;
		}

		platforms[i].code = (unsigned char *) malloc(fpos);
		if (!platforms[i].code) {
			printf("Can't allocate memmory 0x%IX bytes.\n", fpos);
			return -1;
		}
		platforms[i].size = fpos;

		size_t rsize = 1, rnmemb = fpos, rlen;
		rlen = fread(platforms[i].code, rsize, rnmemb, ifp);
		if (rlen == 0) {
			printf("Can't read any data.\n");
			ret = -1;
			goto L_RETURN;
		} else if (rlen < rnmemb) {
			printf("Only read 0x%llX bytes of 0x%IX.\n", rlen, fpos);
			platforms[i].size = rlen;
			// end-of-file
		}
		if (ifp != stdin) fclose(ifp);
	}

	for (i = 0; i < sizeof(platforms)/sizeof(platforms[0]); i++) {
		disasm(&platforms[i], 0x1000, 0, 0);
	}

L_RETURN:
	for (i = 0; i < sizeof(platforms)/sizeof(platforms[0]); i++) {
		if (platforms[i].code) {
			free(platforms[i].code);
			platforms[i].code = NULL;
		}
	}
	return ret;
}
#define FLAGS_TEST	(1<<0)
#define FLAGS_TEST1	(1<<0)
int main(int argc, char * argv[]) {
	int ret = 0;
	const char * ifname = NULL;
	FILE *ifp;
	fpos_t fpos; 
	struct platform platform;
	platform.code = (unsigned char *) NULL;
	int i;
	int flags = 0;

	if (argc < 2) {
#if 0
		return usage(argc, argv);
#else
		test(); return 0;
#endif
	}

	for (i=1; i<argc; i++) {
		if (strcmp("-x", argv[i]) == 0) {
			if ((i+1)<argc) {
				i++;
				opt_XLEN = strtoul(argv[i], NULL, 0);
				if ((opt_XLEN != 32) && (opt_XLEN != 64)) {
					return bad_arg(argc, argv, i, 0);
				}
			} else return bad_arg(argc, argv, i, 0);
		} else if (strcmp("--test", argv[i]) == 0) {
			flags |= FLAGS_TEST;
		} else if (strcmp("--test1", argv[i]) == 0) {
			flags |= FLAGS_TEST1;
		} else if (strcmp("--off", argv[i]) == 0) {
			if ((i+1)<argc) {
				i++;
				opt_offset = strtoul(argv[i], NULL, 0);
			} else return bad_arg(argc, argv, i, 0);
		} else {
			if (!ifname) {
				ifname = argv[i];
			} else return bad_arg(argc, argv, i, argc);
		}
	}

	if (opt_XLEN == 32) {
		platform.arch = CS_ARCH_RISCV;
		platform.mode = CS_MODE_RISCV32|CS_MODE_RISCVC;
		platform.comment = "riscv32";
	} else if (opt_XLEN == 64) {
		platform.arch = CS_ARCH_RISCV;
		platform.mode = CS_MODE_RISCV64|CS_MODE_RISCVC;
		platform.comment = "riscv64";
	}

	if (flags & FLAGS_TEST) test();
	if (flags & FLAGS_TEST1) test1();

	if (!ifname) {
		printf("Need an argument of filename\n");
		return -1;
	}

	printf("ifname=\"%s\"\n", ifname);
	ifp = fopen(ifname, "rb");
	if (!ifp) {
		printf("Cannot open file \"%s\"\n", ifname);
		return -1;
	}

	fseek(ifp, 0, SEEK_END); 
	fgetpos(ifp, &fpos); 
	fseek(ifp, 0, SEEK_SET); 

	if (fpos == 0) {
		printf("Empty file.\n");
		ret = -1;
		goto L_RETURN;
	}

	platform.code = (unsigned char *) malloc(fpos);
	if (!platform.code) {
		printf("Can't allocate memmory 0x%IX bytes.\n", fpos);
		return -1;
	}
	platform.size = fpos;

	size_t rsize = 1, rnmemb = fpos, rlen;
	rlen = fread(platform.code, rsize, rnmemb, ifp);
	if (rlen == 0) {
		printf("Can't read any data.\n");
		ret = -1;
		goto L_RETURN;
	} else if (rlen < rnmemb) {
		printf("Only read 0x%llX bytes of 0x%IX.\n", rlen, fpos);
		platform.size = rlen;
		// end-of-file
	}
	disasm(&platform, 0, opt_offset, 0);

L_RETURN:
	if (platform.code) {
		free(platform.code);
		platform.code = NULL;
	}
	if (ifp != stdin) fclose(ifp);
	return ret;
}
static int usage(int argc, char * argv[]) {
	printf("%s [OPTIONS] filename\n", argv[0]);
	printf("OPTIONS\n");
	printf("-x XLEN         \"64\" (default) or \"32\"\n");
	printf("--off NUMBER    Address offset\n");
	return -1;
}
static int bad_arg(int argc, char * argv[], int n1, int n2) {
	if ((n1 >= n2) || (n2 == 0)) {
		printf("BAD argument[%d] \"%s\"\n", n1, argv[n1]);
	} else {
		int i;
		printf("BAD argument[%d..%d]", n1, n2);
		for (i=n1; (i<n2) && (i<argc); i++) {
			printf(" \"%s\"", argv[i]);
		}
	}
	return -1;
}
