#include <stdio.h>
#include <stdlib.h>

#include <capstone/platform.h>
#include <capstone/capstone.h>

#define RAND_METHOD_MT19937AR_SEP		1
#define RAND_METHOD_MT19937_64			2

// #define CONFIG_RAND_METHOD	RAND_METHOD_MT19937AR_SEP
#define CONFIG_RAND_METHOD	RAND_METHOD_MT19937_64

#if (CONFIG_RAND_METHOD == RAND_METHOD_MT19937AR_SEP)
#include "mt19937ar.sep/mt19937ar.h"
#include "mt19937ar.sep/mt19937ar.c"
#elif (CONFIG_RAND_METHOD == RAND_METHOD_MT19937_64)
#include "mt19937-64/mt64.h"
#include "mt19937-64/mt19937-64.c"
#else
#warning "CONFIG_RAND_METHOD invalid."
#endif

#define LINE_MAX		1024

#define FLAGS_TEST		(1<<0)
#define FLAGS_TEST1		(1<<1)
#define FLAGS_RAND16	(1<<2)
#define FLAGS_RAND32	(1<<3)
static unsigned long opt_XLEN = 64;
static uint64_t opt_vma = 0;
static fpos_t opt_fpos = 0; 
static size_t opt_len = 0; 
static size_t opt_bulk = 0; 
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

static fpos_t file_get_size(FILE *fp) {
	fpos_t pos, size; 

	if (!fp) return -1;
	fgetpos(fp, &pos); // current pos
	fseek(fp, 0, SEEK_END); 
	fgetpos(fp, &size); 
	fseek(fp, pos, SEEK_SET);  // rewind to pos
    return size;
}
static void print_string_hex(const char *comment, unsigned char *str, size_t len)
{
	unsigned char *c;

	printf("%s", comment);
	for (c = str; c < str + len; c++) {
		printf("0x%02x ", *c & 0xff);
	}

	printf("\n");
}

static int catvsprintf(char* s, const char *fmt, va_list ap) {
	char * p = s + strlen(s);
	return vsprintf(p, fmt, ap);
}
static int catsprintf(char* s, const char *fmt, ...) {
    va_list ap;
    int ret;
    va_start(ap, fmt);
    ret = catvsprintf(s, fmt, ap);
    va_end(ap);
    return ret;
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
static void catsprint_insn_bits(char* s, cs_insn *ins) {
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
	catsprintf(s, "%s", buf);
}
static void catsprint_insn_bytes(char* s, cs_insn *ins) {
	int i;
	if (ins->size == 2) {
		for (i=0; i<ins->size; i++) {
			catsprintf(s, "%s%02X", (i==0) ? "" : " ", ins->bytes[i]);
		}
        catsprintf(s, "      ");
	} else if (ins->size == 4) {
		for (i=0; i<ins->size; i++) {
			catsprintf(s, "%s%02X", (i==0) ? "" : " ", ins->bytes[i]);
		}
	} else {
		for (i=0; i<ins->size; i++) {
			catsprintf(s, "%s%02X", (i==0) ? "" : " ", ins->bytes[i]);
		}
	}
}
static void catsprint_insn_detail(char* s, cs_insn *ins) {
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
		catsprintf(s, "op(%u) ", riscv->op_count);

	for (i = 0; i < riscv->op_count; i++) {
		cs_riscv_op *op = &(riscv->operands[i]);
		switch((int)op->type) {
			default:
				catsprintf(s, "[%u]{.type:ERR=%u}", i, (int)op->type);
				break;
			case RISCV_OP_REG:
				catsprintf(s, "[%u]{.type:REG=%s}", i, cs_reg_name(handle, op->reg));
				break;
			case RISCV_OP_IMM:
				catsprintf(s, "[%u]{.type:IMM=0x%" PRIx64 "}", i, op->imm);
				break;
			case RISCV_OP_MEM:
				catsprintf(s, "[%u]{.type:MEM}", i);
				if (op->mem.base != RISCV_REG_INVALID)
					catsprintf(s, "[%u]{.mem.base:REG=%s}",
							i, cs_reg_name(handle, op->mem.base));
				if (op->mem.disp != 0)
					catsprintf(s, "[%u]{.mem.disp:0x%" PRIx64 "}", i, op->mem.disp);

				break;
		}
	}
	
	//print the groups this instruction belongs to
	if (detail->groups_count > 0) {
		catsprintf(s, "%sgroups[", (riscv->op_count) ? " " : "");
		for (n = 0; n < detail->groups_count; n++) {
			catsprintf(s, "%s%s", (n==0) ? "" : " ", cs_group_name(handle, detail->groups[n]));
		}
		catsprintf(s, "]");
	}

}

#define SHOW_NONE		(1<<0)
#define SHOW_ERROR		(1<<1)
#define SHOW_DETAIL		(1<<2)
#define SHOW_DECORATION	(1<<3)
#define SHOW_PLATFORM	(1<<4)
#define SHOW_CODE		(1<<5)
#define SHOW_DISASM		(1<<6)
#define SHOW_END		(1<<7)
static int disasm_ex(struct platform * platform, uint64_t address, int flags, char * dst, size_t max) {
	cs_insn *insn;
	size_t count;

	if (flags == 0) {
		flags = 0
			| SHOW_ERROR
			| SHOW_DETAIL
			| SHOW_DECORATION
			| SHOW_PLATFORM
			| SHOW_CODE
			| SHOW_DISASM
			| SHOW_END
			;
	}

	cs_err err = cs_open(platform->arch, platform->mode, &handle);
	if (err) {
		if (flags & SHOW_ERROR) printf("Failed on cs_open() with error returned: %u\n", err);
		return -1;
	}

	//To turn on or off the Print Details option
	//cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF); 
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	count = cs_disasm(handle, platform->code, platform->size, address, 0, &insn);
	if (count) {
		size_t j;
		char line[LINE_MAX];

		if (flags & SHOW_DECORATION) printf("****************\n");
		if (flags & SHOW_PLATFORM) printf("Platform: %s\n", platform->comment);
		if (flags & SHOW_CODE) print_string_hex("Code:", platform->code, platform->size);
		if (flags & SHOW_DISASM) printf("Disasm:\n");

		line[0] = '\0';
		for (j = 0; j < count; j++) {
			if ((j>0) && (strlen(line)>0)) catsprintf(line, "\n");
			// address
			catsprintf(line, "0x%08" PRIx64 ": ", insn[j].address);
			// bits
			catsprint_insn_bits(line, &insn[j]);
			catsprintf(line, "  ");
			// bytes
			catsprint_insn_bytes(line, &insn[j]);
			catsprintf(line, "  ");
			// mnemonic op
			char mnbuf[64];
			sprintf(mnbuf, "%-6s %s", insn[j].mnemonic, insn[j].op_str);
			catsprintf(line, "%-24s  ", mnbuf);
			catsprint_insn_detail(line, &insn[j]);
			if (flags & SHOW_DETAIL) printf("%s\n", line);
			if (dst) {
				if (strlen(line) < max) {
					strcpy(dst, line);
				} else {
					strncpy(dst, line, max);
				}
			}
		}
		if (flags & SHOW_END) printf("0x%08" PRIx64 ": END\n", insn[j-1].address + insn[j-1].size);

		// free memory allocated by cs_disasm()
		cs_free(insn, count);
	} else {
		if (flags & SHOW_DECORATION) printf("****************\n");
		if (flags & SHOW_PLATFORM) printf("Platform: %s\n", platform->comment);
		if (flags & SHOW_CODE) print_string_hex("Code:", platform->code, platform->size);
		if (flags & SHOW_ERROR) printf("ERROR: Failed to disasm given code!\n");
		return -1;
	}

	if (!(flags & SHOW_NONE)) printf("\n");

	cs_close(&handle);

	return (int) count;
}
static int disasm(struct platform * platform, uint64_t address, int flags) {
	return disasm_ex(platform, address, flags, NULL, 0);
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
		disasm(&platforms[i], 0x1000, 0);
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
		disasm(&platforms[i], 0x80000000, 0);
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
int disasm_file(struct platform * platform, const char * ifname) {
	int ret = 0;
	FILE *ifp;
	fpos_t fsize; 
	size_t data_len;
	char * codebuf;
	platform->code = (unsigned char *) NULL;

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

    fsize = file_get_size(ifp);
	if (opt_fpos > fsize) {
		printf("File start pos > file size.\n");
		ret = -1;
		goto L_RETURN;
	}
	fseek(ifp, opt_fpos, SEEK_SET); 

	if (fsize == 0) {
		printf("Empty file.\n");
		ret = -1;
		goto L_RETURN;
	}
	if (opt_len == 0) {
		opt_len = fsize;
	}
	if (opt_len > (fsize - opt_fpos)) {
		data_len = fsize - opt_fpos;
		printf("Data length truncated to %zu.\n", data_len);
		ret = -1;
		goto L_RETURN;
	} else {
		data_len = opt_len;
	}

	codebuf = (unsigned char *) malloc(data_len);
	if (!codebuf) {
		printf("Can't allocate memmory 0x%IX bytes.\n", data_len);
		return -1;
	}
	platform->size = data_len;

	size_t rsize = 1, rnmemb = data_len, rlen;
	rlen = fread(codebuf, rsize, rnmemb, ifp);
	if (rlen == 0) {
		printf("Can't read any data.\n");
		ret = -1;
		goto L_RETURN;
	} else if (rlen < rnmemb) {
		printf("Only read 0x%llX bytes of 0x%IX.\n", rlen, data_len);
		// end-of-file
	} else {
		printf("Data length 0x%IX.\n", data_len);
	}
	if (opt_bulk) {
		platform->code = codebuf;
		platform->size = rlen;
		ret = disasm(platform, opt_vma, 0
				| SHOW_ERROR
				| SHOW_DETAIL
				// | SHOW_DECORATION
				| SHOW_PLATFORM
				// | SHOW_CODE
				| SHOW_DISASM
				| SHOW_END
				);
		printf("disasm ret = %d\n", ret);
	} else {
		size_t off;
		uint32_t inst;
		for (off=0; off<rlen; ) {
			char line[LINE_MAX];
			line[0] = '\0';
			inst = *((uint32_t*)&codebuf[off]);
			platform->code = (unsigned char*)&inst;
			platform->size = sizeof(inst);
			ret = disasm_ex(platform, opt_vma+off, 0
					| SHOW_NONE
					// | SHOW_ERROR
					// | SHOW_DETAIL
					// | SHOW_DECORATION
					// | SHOW_PLATFORM
					// | SHOW_CODE
					// | SHOW_DISASM
					// | SHOW_END
					, line, sizeof(line)
					);
			if (ret < 0) {
				printf("NV 0x%08X 0x%08llx\n", inst, opt_vma+off);
				off += sizeof(uint32_t);
			} else if (ret > 1) {
#if 1
				char * p;
				for (p=line; *p; p++) {
					if ((*p == '\r') || (*p == '\n')) {
						*p = '\0';
						break;
					}
				}
#endif
				printf("%2u 0x%08X %s\n", ret, inst, line);
				off += sizeof(uint32_t)/ret;
			} else {
				printf("%2u 0x%08X %s\n", ret, inst, line);
				off += sizeof(uint32_t)/ret;
			}
		}
	}

L_RETURN:
	if (codebuf) {
		free(codebuf);
		codebuf = 0;
		platform->code = NULL;
	}
	if (ifp != stdin) fclose(ifp);
	return ret;
}
static uint32_t getrand32(void) {
	static int initialized = 0;
#if (CONFIG_RAND_METHOD == RAND_METHOD_MT19937AR_SEP)
	uint32_t u32;
	if (!initialized) {
		init_genrand(10);
		initialized = 1;
	}
	u32 = genrand_int32();
	// printf("u32 0x%08X\n", u32);
	return u32;
#elif (CONFIG_RAND_METHOD == RAND_METHOD_MT19937_64)
	uint64_t u64;
	if (!initialized) {
		init_genrand64(10);
		initialized = 1;
	}
	u64 = genrand64_int64();
	// printf("u64 0x%016llX\n", u64);
	return (uint32_t)u64;
#else
#warning "CONFIG_RAND_METHOD invalid."
#endif
}
static int rand_gen(struct platform * platform, size_t max, int flags) {
	int ret = 0;
	size_t i;
	uint32_t inst;
	size_t nv_count = 0;
	size_t ok_count = 0;

	for (i=0; nv_count<max; i++) {
		char line[LINE_MAX];
		line[0] = '\0';
		inst = getrand32();
		if (!(flags & FLAGS_RAND16)) {
			inst = (inst << 2) | 0x3;
		}

		platform->code = (unsigned char*)&inst;
		platform->size = sizeof(inst);
		ret = disasm_ex(platform, 0x1000, 0
				| SHOW_NONE
				// | SHOW_ERROR
				// | SHOW_DETAIL
				// | SHOW_DECORATION
				// | SHOW_PLATFORM
				// | SHOW_CODE
				// | SHOW_DISASM
				// | SHOW_END
				, line, sizeof(line)
				);
		if (ret < 0) {
			nv_count ++;
			printf("NV 0x%08X\n", inst);
		} else {
			ok_count ++;
			printf("OK 0x%08X \"%s\"\n", inst, line);
		}
	};
    return ret;
}
int main(int argc, char * argv[]) {
	const char * ifname = NULL;
	struct platform platform;
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
		} else if (strcmp("--fpos", argv[i]) == 0) {
			if ((i+1)<argc) {
				i++;
				opt_fpos = strtoul(argv[i], NULL, 0);
			} else return bad_arg(argc, argv, i, 0);
		} else if (strcmp("--len", argv[i]) == 0) {
			if ((i+1)<argc) {
				i++;
				opt_len = strtoul(argv[i], NULL, 0);
			} else return bad_arg(argc, argv, i, 0);
		} else if (strcmp("--vma", argv[i]) == 0) {
			if ((i+1)<argc) {
				i++;
				opt_vma = strtoul(argv[i], NULL, 0);
			} else return bad_arg(argc, argv, i, 0);
		} else if (strcmp("--bulk", argv[i]) == 0) {
			opt_bulk = 1; 
		} else if (strcmp("--rand16", argv[i]) == 0) {
			// TODO:ランダムな16ビットの命令(RVC)を生成する
			flags |= FLAGS_RAND16;
		} else if (strcmp("--rand32", argv[i]) == 0) {
			// TODO:ランダムな32ビットの命令(RV32/64)を生成する
			flags |= FLAGS_RAND32;
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

	if (flags & FLAGS_RAND32) return rand_gen(&platform, 100, flags);
	if (flags & FLAGS_TEST) test();
	if (flags & FLAGS_TEST1) test1();
    return disasm_file(&platform, ifname);
}
static int usage(int argc, char * argv[]) {
	printf("%s [OPTIONS] filename\n", argv[0]);
	printf("OPTIONS\n");
	printf("-x XLEN         \"64\" (default) or \"32\"\n");
	printf("--fpos NUMBER   File seek offset (default: head of the file)\n");
	printf("--len NUMBER    Data length (default: file size - fpos)\n");
	printf("--vma NUMBER    Address offset\n");
	printf("--bulk          Bulk disasm (default: step-by-step)\n");
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
