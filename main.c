#include <stdint.h> // for uint*_t types
#include <stdlib.h> // for malloc and so on
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "kuznechik.h"

static void xd(uint8_t *p, ssize_t size) {
	for (uint8_t * c = p; c < p + size; c++) {
		printf("0x%02X ", *c);
	}
	printf("\n");
}

typedef struct text_t {
	uint8_t *p;
	size_t len;
} text_t;


text_t *kuz_encrypt_ofb(uint8_t kuz_master_key[32], vect_t *iv, text_t *text) {
	// 0. Setup rk:
	round_keys_t rk = {};
	GOST_Kuz_set_key(kuz_master_key, &rk);

	size_t codelen = text->len / sizeof(vect_t) * sizeof(vect_t);
	uint8_t *last_block = text->p + codelen;

	if (codelen < text->len) {
		codelen += sizeof(vect_t);
	}

	text_t *code = (text_t*) malloc (sizeof(text_t));
	code->len = codelen;
	code->p   = (uint8_t *) malloc(codelen);

	if (!code->p) {
		perror("Allocation failed");
		exit(1);
	}

	uint8_t *p, *cp;
	for (p = text->p, cp = code->p; p < last_block; p += sizeof(vect_t), cp += sizeof(vect_t)) {
		GOST_Kuz_encrypt_block(&rk, iv, iv);
		GOST_Kuz_X(iv, (vect_t *) p, (vect_t *) cp);
	}

	if (text->len < codelen) {
		// adds padding
		vect_t last = {};
		memcpy(last.b, last_block, text->p + text->len - last_block);

		GOST_Kuz_encrypt_block(&rk, iv, iv);
		GOST_Kuz_X(iv, &last, (vect_t *) cp);
	}

	return code;
}

text_t *kuz_decrypt_ofb(uint8_t kuz_master_key[32], vect_t *iv, text_t *code) {
	// 0. Setup rk:
	round_keys_t rk = {};
	GOST_Kuz_set_key(kuz_master_key, &rk);

	text_t *text = (text_t*) malloc (sizeof(text_t));
	text->len = code->len;
	text->p   = (uint8_t *) malloc(code->len);

	if (!text->p) {
		perror("Allocation failed");
		exit(1);
	}

	uint8_t *p, *cp;
	for (p = text->p, cp = code->p; cp < code->p + code->len; p += sizeof(vect_t), cp += sizeof(vect_t)) {
		GOST_Kuz_encrypt_block(&rk, iv, iv);
		GOST_Kuz_X(iv, (vect_t *) cp, (vect_t *) p);
	}

	return text;
}

typedef enum {
	ENCRYPT = 1,
	DECRYPT = 2,
} cmd_t;

typedef struct {
	char const * inf;
	char const * outf;
	char const * keyf;
	char const * ivf;

	cmd_t cmd;
	uint8_t master_key[32];
	vect_t iv;
} args_t;

static void usage(int status) {
	fprintf(stderr, "Usage: kuznetchik [-e|-d] [options]\n");
	fprintf(stderr, "\t-e                Encodes given message\n");
	fprintf(stderr, "\t-d                Decodes given message\n");
	fprintf(stderr, "\t-k <keyfile>      Path to master-key file\n\n");
	fprintf(stderr, "\t-i <input file>   [optional] Path to input file. Default stdin\n");
	fprintf(stderr, "\t-o <output file>  [optional] Path to output file. Default stdout\n");
	fprintf(stderr, "\t-v <iv file>      [optional] Path to iv file. Default 0x00\n\n");
	fprintf(stderr, "\t-h                Prints this help\n");

	exit(status);
}

args_t parse(int argc, char const *argv[]) {
	args_t args = {};
	for (int i = 1; i < argc; i++) {
		if (0) {
		} else if (!strcmp(argv[i], "-e")) {
			args.cmd = ENCRYPT;
		} else if (!strcmp(argv[i], "-d")) {
			args.cmd = DECRYPT;
		} else if (!strcmp(argv[i], "-k")) {
			args.keyf = argv[++i];
		} else if (!strcmp(argv[i], "-i")) {
			args.inf = argv[++i];
		} else if (!strcmp(argv[i], "-o")) {
			args.outf = argv[++i];
		} else if (!strcmp(argv[i], "-v")) {
			args.ivf = argv[++i];
		} else if (!strcmp(argv[i], "-h")) {
			usage(0);
		} else {
			fprintf(stderr, "Unknown option given: %s\n", argv[i]);
			usage(1);
		}
	}

	if (!args.cmd) {
		fprintf(stderr, "Command -e or -d is required\n");
		usage(1);
	}

	if (args.inf) {
		int fd = open(args.inf, O_RDONLY);
		if (-1 == fd) {
			perror("Open of input file failed");
			exit(1);
		}
		if (-1 == dup2(fd, 0)) { // duplicate input file to stdin
			perror("dup2 failed");
			exit(1);
		}
	}

	if (args.outf) {
		int fd = open(args.outf, O_WRONLY | O_TRUNC | O_CREAT, 0600);
		if (-1 == fd) {
			perror("Open of output file failed");
			exit(1);
		}
		if (-1 == dup2(fd, 1)) { // duplicate output file to stdout
			perror("dup2 failed");
			exit(1);
		}
	}

	if (args.keyf) {
		int fd = open(args.keyf, O_RDONLY);
		if (-1 == fd) {
			perror("Open of keyfile failed");
			exit(1);
		}
		int r = read(fd, args.master_key, sizeof(args.master_key));
		if (sizeof(args.master_key) != r) {
			fprintf(stderr, "Master key is less than 32 bytes: %d\n", r);
			exit(1);
		}
		char p;
		r = read(fd, &p, 1);
		if (r > 0) {
			fprintf(stderr, "Master key file is bigger than 32 bytes!\n");
			exit(1);
		}
	} else {
		fprintf(stderr, "Path to master key is required (-k option)\n");
		usage(1);
	}

	if (args.ivf) {
		int fd = open(args.ivf, O_RDONLY);
		if (-1 == fd) {
			perror("Open of iv file failed");
			exit(1);
		}
		int r = read(fd, &args.iv, sizeof(args.iv));
		if (sizeof(args.iv) != r) {
			fprintf(stderr, "IV key is less than 16 bytes: %d\n", r);
			exit(1);
		}
		char p;
		r = read(fd, &p, 1);
		if (r > 0) {
			fprintf(stderr, "IV file is bigger than 16 bytes!\n");
			exit(1);
		}
	}

	return args;
}

int main(int argc, char const *argv[]) {
	args_t args = parse(argc, argv);

	round_keys_t rk = {};
	GOST_Kuz_set_key(args.master_key, &rk);

	size_t BUF_SIZE = 4096;

	uint8_t buffer[BUF_SIZE]; memset(buffer, 0, BUF_SIZE);
	uint8_t out[BUF_SIZE];    memset(out, 0, BUF_SIZE);

	for (;;) {
		int rd = read(0, buffer, sizeof(buffer));
		if (-1 == rd) {
			perror("input descriptor unexpectedly was closed");
			exit(1);
		}
		if ((size_t) rd < sizeof(buffer)) { // we have to add padding
			if (rd == 0) {
				break; // no read. finish loop
			}

			if (rd % 16) { // if padding is needed
				if (args.cmd == DECRYPT) {
					fprintf(stderr, "Invalid padding for decode\n");
				}
				memset(buffer + rd, 0, BUF_SIZE - rd); // set other bytes of buffer to 0
				rd += 16 - rd % 16;
			}
		}

		uint8_t *p = buffer;
		uint8_t *cp = out;
		for (; p < &buffer[rd]; p += sizeof(vect_t), cp += sizeof(vect_t)) {
			GOST_Kuz_encrypt_block(&rk, &args.iv, &args.iv);
			GOST_Kuz_X(&args.iv, (vect_t *) p, (vect_t *) cp);
		}

		int w = write(1, out, rd); // we have to write exactly read amount of bytes
		if (-1 == w) {
			perror("Unexpected error on write");
			exit(1);
		}
	}

	return 0;
}
