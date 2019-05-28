PROGRAM=test
C_SRCS=test.c

$(PROGRAM): $(C_SRCS)
	$(CC) -lssl -lcrypto -o $(PROGRAM) $(C_SRCS);

pbeWithMD5AndDES: pbeWithMD5AndDES.c
	$(CC) -lssl -lcrypto -o pbeWithMD5AndDES pbeWithMD5AndDES.c
