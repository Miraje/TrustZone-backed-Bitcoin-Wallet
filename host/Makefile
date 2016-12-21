APP_NAME = wallet

CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

OBJS = extern.o test_helpers.o test_stream.o test_prandom.o test_wallet.o test_transaction.o test_performance.o main.o stream_comm.o user_interface.o endian.o messages.pb.o pb_decode.o pb_encode.o wallet.o prandom.o bignum256.o storage_common.o transaction.o baseconv.o tz_functions.o

CFLAGS += -Wall -I../ta/include -I$(TEEC_EXPORT)/include
LDADD += -lteec -L$(TEEC_EXPORT)/lib

$(APP_NAME): $(OBJS)
	$(CC) $(LDADD) -o $@ $^

.PHONY: clean
clean:
	rm -f $(OBJS) $(APP_NAME)

.PHONY: all
all: clean $(APP_NAME)
