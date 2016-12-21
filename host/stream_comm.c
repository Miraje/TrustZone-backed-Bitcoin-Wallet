/** \file
  *
  * \brief TO DO YET!!!!
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "common.h"
#include "ecdsa.h"
#include "endian.h"
#include "extern.h"
#include "hwinterface.h"
#include "messages.pb.h"
#include "pb.h"
#include "pb_decode.h"
#include "pb_encode.h"
#include "prandom.h"
#include "stream_comm.h"
#include "test_stream.h"
#include "transaction.h"
#include "tz_functions.h"
#include "user_interface.h"
#include "wallet.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Prototypes for forward-referenced functions. */
bool mainInputStreamCallback(pb_istream_t *stream, uint8_t *buf, size_t count);
bool mainOutputStreamCallback(pb_ostream_t *stream, const uint8_t *buf, size_t count);
static void writeFailureString(StringSet set, uint8_t spec);

/**
 * \defgroup TestStreamVariables Test variables to be used in stream_comm functions.
 *
 * @{
 */
/** Contents of a test stream (to read from). */
static uint8_t* stream;
/** 0-based index into #stream specifying which byte will be read next. */
static uint32_t stream_byte_index;
/** Length of the test stream, in number of bytes. */
static uint32_t stream_length;
/** Whether to use a test stream consisting of an infinite stream of zeroes. */
static bool is_stream_of_infinite_zeros;
/**@}*/

/** Argument for writeStringCallback() which determines what string it will
  * write. Don't put this on the stack, otherwise the consequences of a
  * dangling pointer are less secure. */
static struct StringSetAndSpec string_arg;

/** Alternate copy of #string_arg, for when more than one string needs to be
  * written. */
static struct StringSetAndSpec string_arg_alt;

/** Length of current packet's payload. */
static uint32_t payload_length;

/** Arbitrary host-supplied bytes which are sent to the host to assure it that
  * a reset hasn't occurred. */
static uint8_t session_id[64];

/** Number of valid bytes in #session_id. */
static size_t session_id_length;

/** The transaction hash of the most recently approved transaction. This is
  * stored so that if a transaction needs to be signed multiple times (eg.
  * if it has more than one input), the user doesn't have to approve every
  * one. */
static uint8_t prev_transaction_hash[32];

/** false means disregard #prev_transaction_hash, true means
  * that #prev_transaction_hash is valid. */
static bool prev_transaction_hash_valid;

/** Storage for fields of SignTransaction message. Needed for the
  * signTransactionCallback() callback function. */
static SignTransaction sign_transaction;

/** Current number of wallets; used for the listWalletsCallback() callback
  * function. */
static uint32_t number_of_wallets;

/** Double SHA-256 of a field parsed by hashFieldCallback(). */
static uint8_t field_hash[32];

/** Whether #field_hash has been set. */
static bool field_hash_set;

/** When sending test packets, the OTP stored here will be used instead of
  * a generated OTP. This allows the test cases to be static. */
static char test_otp[OTP_LENGTH] = {'1', '2', '3', '4', '\0'};

/** Pointer to bytes of entropy to send to the host; used for
  * the getEntropyCallback() callback function. */
static uint8_t *entropy_buffer;

/** Number of bytes of entropy to send to the host; used for
  * the getEntropyCallback() callback function. */
static size_t num_entropy_bytes;

/** nanopb input stream which uses mainInputStreamCallback() as a stream
  * callback. */
pb_istream_t main_input_stream = {&mainInputStreamCallback, NULL, 0, NULL};
/** nanopb output stream which uses mainOutputStreamCallback() as a stream
  * callback. */
pb_ostream_t main_output_stream = {&mainOutputStreamCallback, NULL, 0, 0, NULL};

/** Helper function for getString() and getStringLength(). It fetches
  * the needed string for a (set, spec) pair.
  * \param set Specifies which set of strings to use; should be
  *            one of #StringSetEnum.
  * \param spec Specifies which string to get the character from. The
  *             interpretation of this depends on the value of set;
  *             see #StringSetEnum for clarification.
  * \return A pointer to the actual string.
  */
static const char* getStringInternal(StringSet set, uint8_t spec)
{
	const char *str;

	/* All sets are defined in hwinterface.h */
	/* All the string are defined here - strings.c */

	/* spec's for this set are defined in hwinterface.h */
	if (set == STRINGSET_MISC)
	{
		switch (spec)
		{
			case MISCSTR_VENDOR:
				str = str_MISCSTR_VENDOR;
				break;
			case MISCSTR_PERMISSION_DENIED_USER:
				str = str_MISCSTR_PERMISSION_DENIED_USER;
				break;
			case MISCSTR_INVALID_PACKET:
				str = str_MISCSTR_INVALID_PACKET;
				break;
			case MISCSTR_PARAM_TOO_LARGE:
				str = str_MISCSTR_PARAM_TOO_LARGE;
				break;
			case MISCSTR_PERMISSION_DENIED_HOST:
				str = str_MISCSTR_PERMISSION_DENIED_HOST;
				break;
			case MISCSTR_UNEXPECTED_PACKET:
				str = str_MISCSTR_UNEXPECTED_PACKET;
				break;
			case MISCSTR_OTP_MISMATCH:
				str = str_MISCSTR_OTP_MISMATCH;
				break;
			case MISCSTR_CONFIG:
				str = str_MISCSTR_CONFIG;
				break;
			default:
				str = str_UNKNOWN;
				break;
		}
	}
	/* spec's for this set are defined in wallet.h */
	else if (set == STRINGSET_WALLET)
	{
		switch (spec)
		{
			case WALLET_FULL:
				str = str_WALLET_FULL;
				break;
			case WALLET_EMPTY:
				str = str_WALLET_EMPTY;
				break;
			case WALLET_READ_ERROR:
				str = str_WALLET_READ_ERROR;
				break;
			case WALLET_WRITE_ERROR:
				str = str_WALLET_WRITE_ERROR;
				break;
			case WALLET_NOT_THERE:
				str = str_WALLET_NOT_THERE;
				break;
			case WALLET_NOT_LOADED:
				str = str_WALLET_NOT_LOADED;
				break;
			case WALLET_INVALID_HANDLE:
				str = str_WALLET_INVALID_HANDLE;
				break;
			case WALLET_BACKUP_ERROR:
				str = str_WALLET_BACKUP_ERROR;
				break;
			case WALLET_RNG_FAILURE:
				str = str_WALLET_RNG_FAILURE;
				break;
			case WALLET_INVALID_WALLET_NUM:
				str = str_WALLET_INVALID_WALLET_NUM;
				break;
			case WALLET_INVALID_OPERATION:
				str = str_WALLET_INVALID_OPERATION;
				break;
			case WALLET_ALREADY_EXISTS:
				str = str_WALLET_ALREADY_EXISTS;
				break;
			case WALLET_BAD_ADDRESS:
				str = str_WALLET_BAD_ADDRESS;
				break;
			default:
				str = str_UNKNOWN;
				break;
		}
	}
	/* spec's for this set are defined in transaction.h */
	else if (set == STRINGSET_TRANSACTION)
	{
		switch (spec)
		{
			case TRANSACTION_INVALID_FORMAT:
				str = str_TRANSACTION_INVALID_FORMAT;
				break;
			case TRANSACTION_TOO_MANY_INPUTS:
				str = str_TRANSACTION_TOO_MANY_INPUTS;
				break;
			case TRANSACTION_TOO_MANY_OUTPUTS:
				str = str_TRANSACTION_TOO_MANY_OUTPUTS;
				break;
			case TRANSACTION_TOO_LARGE:
				str = str_TRANSACTION_TOO_LARGE;
				break;
			case TRANSACTION_NON_STANDARD:
				str = str_TRANSACTION_NON_STANDARD;
				break;
			case TRANSACTION_INVALID_AMOUNT:
				str = str_TRANSACTION_INVALID_AMOUNT;
				break;
			case TRANSACTION_INVALID_REFERENCE:
				str = str_TRANSACTION_INVALID_REFERENCE;
				break;
			default:
				str = str_UNKNOWN;
				break;
		}
	}
	else
		str = str_UNKNOWN;

	return str;
}

/** Get the length of one of the device's strings.
  * \param set Specifies which set of strings to use; should be
  *            one of #StringSetEnum.
  * \param spec Specifies which string to get the character from. The
  *             interpretation of this depends on the value of set;
  *             see #StringSetEnum for clarification.
  * \return The length of the string, in number of characters.
  */
uint16_t getStringLength(StringSet set, uint8_t spec)
{
	/* Use helper function to get the string */
	 return (uint16_t)strlen(getStringInternal(set, spec));
}

/** Obtain one character from one of the device's strings.
  * \param set Specifies which set of strings to use; should be
  *            one of #StringSetEnum defined in hwinterface.h.
  * \param spec Specifies which string to get the character from. The
  *             interpretation of this depends on the value of set;
  *             see #StringSetEnum for clarification.
  * \param pos The position of the character within the string; 0 means first,
  *            1 means second etc.
  * \return The character from the specified string.
  */
char getString(StringSet set, uint8_t spec, uint16_t pos)
{
	/* Attempting to read beyond end of string */
	assert(pos < getStringLength(set, spec));

	/* Use helper function to get the string */
	return getStringInternal(set, spec)[pos];
}

/** Sets input stream (what will be read by streamGetOneByte()) to the
  * contents of a buffer.
  * \param buffer The test stream data. Each call to streamGetOneByte() will
  *               return successive bytes from this buffer.
  * \param length The length of the buffer, in number of bytes.
  */
void setTestInputStream(const uint8_t *buffer, uint32_t length)
{
	/* Guarantee a new strean is being used */
	if (stream != NULL)
		free(stream);

	/* Allocate memory for stream */
	stream = (uint8_t*)malloc(length * sizeof(uint8_t));

	if (stream == NULL)
	{
		printf("ERROR: Out of memory for stream.\n");
		exit(1);
	}

	/* Copy buffer content to stream */
	memcpy(stream, buffer, length);

	/* Define stream charactiristics */
	stream_length = length;
	stream_byte_index = 0;
	is_stream_of_infinite_zeros = false;
}

/** Sets the input stream (what will be read by streamGetOneByte()) to an
  * infinite stream of zeroes.
  */
void setInfiniteZeroInputStream(void)
{
	is_stream_of_infinite_zeros = true;
}

/** Grab one byte from the communication stream. There is no way for this
  * function to indicate a read error. This is intentional; it
  * makes program flow simpler (no need to put checks everywhere). As a
  * consequence, this function should only return if the received byte is
  * free of read errors.
  *
  * Previously, if a read or write error occurred, processPacket() would
  * return, an error message would be displayed and execution would halt.
  * There is no reason why this couldn't be done inside streamGetOneByte()
  * or streamPutOneByte(). So nothing was lost by omitting the ability to
  * indicate read or write errors.
  *
  * Perhaps the argument can be made that if this function indicated read
  * errors, the caller could attempt some sort of recovery. Perhaps
  * processPacket() could send something to request the retransmission of
  * a packet. But retransmission requests are something which can be dealt
  * with by the implementation of the stream. Thus a caller of
  * streamGetOneByte() will assume that the implementation handles things
  * like automatic repeat request, flow control and error detection and that
  * if a true "stream read error" occurs, the communication link is shot to
  * bits and nothing the caller can do will fix that.
  * \return The received byte.
  */
uint8_t streamGetOneByte(void)
{
	if (is_stream_of_infinite_zeros)
		return 0;

	if (stream == NULL)
	{
		printf("ERROR: Tried to read a stream whose contents weren't set.\n");
		exit(1);
	}

	if (stream_byte_index >= stream_length)
	{
		printf("ERROR: Tried to read past the end of the stream.\n");
		exit(1);
	}

	return stream[stream_byte_index++];
}

void streamGetBytes(uint8_t * out, uint8_t length)
{
	if (is_stream_of_infinite_zeros)
	{
		memset(out, 0, length);
		return;
	}

	if (stream == NULL)
	{
		printf("ERROR: Tried to read a stream whose contents weren't set.\n");
		exit(1);
	}

	if (stream_byte_index >= stream_length)
	{
		printf("ERROR: Tried to read past the end of the stream.\n");
		exit(1);
	}

	if ((stream_byte_index + (uint32_t)length ) > stream_length)
	{
		printf("ERROR: Tried to read past the end of the stream.\n");
		exit(1);
	}

	memcpy(out, &stream[stream_byte_index], length);

	stream_byte_index += (uint32_t)length;
}


/** Send one byte to the communication stream. There is no way for this
  * function to indicate a write error. This is intentional; it
  * makes program flow simpler (no need to put checks everywhere). As a
  * consequence, this function should only return if the byte was sent
  * free of write errors.
  *
  * See streamGetOneByte() for some justification about why write errors
  * aren't indicated by a return value.
  * \param one_byte The byte to send.
  */
void streamPutOneByte(uint8_t one_byte)
{
	printf(" %02x", (int)one_byte);

	if (is_test_stream)
		writeResponseByte(one_byte);
}

/** Read bytes from the stream.
  * \param buffer The byte array where the bytes will be placed. This must
  *               have enough space to store length bytes.
  * \param length The number of bytes to read.
  */
static void getBytesFromStream(uint8_t *buffer, uint8_t length)
{
	uint8_t i;

	for (i = 0; i < length; i++)
		buffer[i] = streamGetOneByte();

	payload_length -= length;
}

/** Write a number of bytes to the output stream.
  * \param buffer The array of bytes to be written.
  * \param length The number of bytes to write.
  */
static void writeBytesToStream(const uint8_t *buffer, size_t length)
{
	size_t i;

	for (i = 0; i < length; i++)
		streamPutOneByte(buffer[i]);
}

/** nanopb input stream callback which uses streamGetOneByte() to get the
  * requested bytes.
  * \param stream Input stream object that issued the callback.
  * \param buf Buffer to fill with requested bytes.
  * \param count Requested number of bytes.
  * \return true on success, false on failure (nanopb convention).
  */
bool mainInputStreamCallback(pb_istream_t *stream, uint8_t *buf, size_t count)
{
	size_t i;

	if (buf == NULL)
		fatalError(); /* This should never happen. */

	for (i = 0; i < count; i++)
	{
		if (payload_length == 0)
		{
			/* Attempting to read past end of payload. */
			stream->bytes_left = 0;
			return false;
		}

		buf[i] = streamGetOneByte();
		payload_length--;
	}

	return true;
}

/** nanopb output stream callback which uses streamPutOneByte() to send a byte
  * buffer.
  * \param stream Output stream object that issued the callback.
  * \param buf Buffer with bytes to send.
  * \param count Number of bytes to send.
  * \return true on success, false on failure (nanopb convention).
  */
bool mainOutputStreamCallback(pb_ostream_t *stream, const uint8_t *buf, size_t count)
{
	writeBytesToStream(buf, count);
	return true;
}

/** nanopb field callback which will write the string specified by arg.
  * \param stream Output stream to write to.
  * \param field Field which contains the string.
  * \param arg Pointer to #StringSetAndSpec structure specifying the string
  *            to write.
  * \return true on success, false on failure (nanopb convention).
  */
bool writeStringCallback(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	uint16_t i;
	uint16_t length;
	char c;
	struct StringSetAndSpec **ptr_arg_s;
	struct StringSetAndSpec *arg_s;

	ptr_arg_s = (struct StringSetAndSpec **)arg;

	if (ptr_arg_s == NULL)
		fatalError(); /* This should never happen */

	arg_s = *ptr_arg_s;

	if (arg_s == NULL)
		fatalError(); /* This should never happen */

	length = getStringLength(arg_s->next_set, arg_s->next_spec);

	if (!pb_encode_tag_for_field(stream, field))
		return false;

	/* Cannot use pb_encode_string() because it expects a pointer to the
	 * contents of an entire string; getString() does not return such a
	 * pointer.
	 */
	if (!pb_encode_varint(stream, (uint64_t)length))
		return false;

	for (i = 0; i < length; i++)
	{
		c = getString(arg_s->next_set, arg_s->next_spec, i);

		if (!pb_write(stream, (uint8_t *)&c, 1))
			return false;
	}

	return true;
}

/** nanopb field callback which will write repeated WalletInfo messages; one
  * for each wallet on the device.
  * \param stream Output stream to write to.
  * \param field Field which contains the WalletInfo submessage.
  * \param arg Unused.
  * \return true on success, false on failure (nanopb convention).
  */
bool listWalletsCallback(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	uint32_t i;
	WalletInfo message_buffer;
	uint32_t version;

	for (i = 0; i < number_of_wallets; i++)
	{
		message_buffer.wallet_number = i;
		message_buffer.wallet_name.size = NAME_LENGTH;
		message_buffer.wallet_uuid.size = UUID_LENGTH;

		if (getWalletInfo(&version,	message_buffer.wallet_name.bytes, message_buffer.wallet_uuid.bytes, i) != WALLET_NO_ERROR)
			return true; /* It's too late to return an error message, so cut off the array now */

		if (version != VERSION_NOTHING_THERE)
		{
			if (!pb_encode_tag_for_field(stream, field))
				return false;

			if (!pb_encode_submessage(stream, WalletInfo_fields, &message_buffer))
				return false;
		}
	}

	return true;
}

/** nanopb field callback which calculates the double SHA-256 of an arbitrary
  * number of bytes. This is useful if we don't care about the contents of a
  * field but want to compress an arbitrarily-sized field into a fixed-length
  * variable.
  * \param stream Input stream to read from.
  * \param field Field which contains an arbitrary number of bytes.
  * \param arg Unused.
  * \return true on success, false on failure (nanopb convention).
  */
bool hashFieldCallback(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
	uint8_t one_byte;
	//HashState hs;
	uint32_t hs[8];

	//sha256Begin(&hs);
	sha256BeginTZ(1);

	while (stream->bytes_left > 0)
    {
		if (!pb_read(stream, &one_byte, 1))
			return false;

        //sha256WriteByte(&hs, one_byte);
        sha256WriteTZ(&one_byte, (uint32_t)1, 1);
    }

	//sha256FinishDouble(&hs);
	sha256FinishDoubleTZ(hs, (uint32_t)32, 1);

	//writeHashToByteArray(field_hash, &hs, true);
	writeHashToByteArrayTZ(field_hash, hs, true);

	field_hash_set = true;

    return true;
}

/** Read but ignore #payload_length bytes from input stream. This will also
  * set #payload_length to 0 (if everything goes well). This function is
  * useful for ensuring that the entire payload of a packet is read from the
  * stream device.
  */
static void readAndIgnoreInput(void)
{
	if (payload_length > 0)
		for (; payload_length > 0; payload_length--)
			streamGetOneByte();
}

/** Function used to receive the packet header and process it.
  * \return Message ID (i.e. command type) of packet.
  */
static uint16_t receivePacketHeader(void)
{
	uint8_t buffer[4];
	uint16_t message_id;

	getBytesFromStream(buffer, 2);

	if ((buffer[0] != '#') || (buffer[1] != '#'))
		fatalError(); /* invalid header */

	getBytesFromStream(buffer, 2);

	message_id = (uint16_t)(((uint16_t)buffer[0] << 8) | ((uint16_t)buffer[1]));

	getBytesFromStream(buffer, 4);

	payload_length = readU32BigEndian(buffer);

	/* TODO: size_t not generally uint32_t */
	/* TODO: necessary a timer or not? */
	main_input_stream.bytes_left = payload_length;

	return message_id;
}

/** Receive a message from the stream #main_input_stream.
  * \param fields Field description array.
  * \param dest_struct Where field data will be stored.
  * \return false on success, true if a parse error occurred.
  */
static bool receiveMessage(const pb_field_t fields[], void *dest_struct)
{
	bool response;

	response = pb_decode(&main_input_stream, fields, dest_struct);

	/* In order for the message to be considered valid, it must also occupy
	 	the entire payload of the packet. */
	if ((payload_length > 0) || !response)
	{
		readAndIgnoreInput();
		writeFailureString(STRINGSET_MISC, MISCSTR_INVALID_PACKET);
		return true;
	}
	else
		return false;
}

/** Send a packet.
  * \param message_id The message ID of the packet.
  * \param fields Field description array.
  * \param src_struct Field data which will be serialised and sent.
  */
static void sendPacket(uint16_t message_id, const pb_field_t fields[], const void *src_struct)
{
	uint8_t buffer[4];
	pb_ostream_t substream;

	/*
	 * From PROTOCOL, the current received packet must be fully consumed
	 * before any response can be sent.
	 */
	assert(payload_length == 0);

	/*
	 * Use a non-writing substream to get the length of the message without
	 * storing it anywhere.
	 */
	substream.callback = NULL;
	substream.state = NULL;
	substream.max_size = MAX_SEND_SIZE;
	substream.bytes_written = 0;

	if (!pb_encode(&substream, fields, src_struct))
		fatalError();

	printf("Message sent to host:");

	/* Send packet header. */
	streamPutOneByte('#');
	streamPutOneByte('#');
	streamPutOneByte((uint8_t)(message_id >> 8));
	streamPutOneByte((uint8_t)message_id);
	writeU32BigEndian(buffer, substream.bytes_written);
	writeBytesToStream(buffer, 4);

	/* Send actual message. */
	main_output_stream.bytes_written = 0;
	main_output_stream.max_size = substream.bytes_written;

	if (!pb_encode(&main_output_stream, fields, src_struct))
		fatalError();

	printf("\n");
}

/** Begin ButtonRequest interjection. This asks the host whether it is okay
  * to prompt the user and wait for a button press.
  * \param command The action to ask the user about. See #AskUserCommandEnum.
  * \return false if the user accepted, true if the user or host denied.
  */
static bool buttonInterjection(AskUserCommand command)
{
	ButtonRequest button_request;
	ButtonAck button_ack;
	ButtonCancel button_cancel;
	uint16_t message_id;
	bool receive_failure;

	memset(&button_request, 0, sizeof(button_request));

	sendPacket(PACKET_TYPE_BUTTON_REQUEST, ButtonRequest_fields, &button_request);

	message_id = receivePacketHeader();

	if (message_id == PACKET_TYPE_BUTTON_ACK)
	{
		/* Host will allow button press */
		receive_failure = receiveMessage(ButtonAck_fields, &button_ack);

		if (receive_failure)
			return true;
		else
		{
			if (userDenied(command))
			{
				writeFailureString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED_USER);
				return true;
			}
			else
				return false;
		}
	}
	else if (message_id == PACKET_TYPE_BUTTON_CANCEL)
	{
		/*
		 * Host will not allow button press. The only way to safely deal with this
		 * is to unconditionally deny permission for the requested action.
		 */
		receive_failure = receiveMessage(ButtonCancel_fields, &button_cancel);

		if (!receive_failure)
			writeFailureString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED_HOST);

		return true;
	}
	else
	{
		/* Unexpected message */
		readAndIgnoreInput();
		writeFailureString(STRINGSET_MISC, MISCSTR_UNEXPECTED_PACKET);
		return true;
	}
}

/** Translates a return value from one of the wallet functions into a Success
  * or Failure response packet which is written to the stream.
  * \param r The return value from the wallet function.
  */
static void translateWalletError(WalletErrors r)
{
	Success message_buffer;

	if (r == WALLET_NO_ERROR)
		sendPacket(PACKET_TYPE_SUCCESS, Success_fields, &message_buffer);
	else
		writeFailureString(STRINGSET_WALLET, (uint8_t)r);
}

/** nanopb field callback for signature data of SignTransaction message. This
  * does (or more accurately, delegates) all the "work" of transaction
  * signing: parsing the transaction, asking the user for approval, generating
  * the signature and sending the signature.
  * \param stream Input stream to read from.
  * \param field Field which contains the signature data.
  * \param arg Unused.
  * \return true on success, false on failure (nanopb convention).
  */
bool signTransactionCallback(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
	TransactionErrors response;
	uint8_t sig_hash[32];
	uint8_t transaction_hash[32];
	bool approved;
	uint8_t signature_length;
	bool permission_denied;
	AddressHandle ah;
	//uint8_t private_key[32];
	Signature message_buffer;
	WalletErrors wallet_return;

	/* Validate transaction and calculate hashes of it*/
	clearOutputsSeen();

	response = parseTransaction(sig_hash, transaction_hash, stream->bytes_left);

	/*
	 * parseTransaction() always reads transaction_length bytes, even if parse
	 * errors occurs. These next two lines are a bit of a hack to account for
	 * differences between streamGetOneByte() and pb_read(stream, buf, 1).
	 * The intention is that transaction.c doesn't have to know anything about
	 * protocol buffers.
	 */
	payload_length -= stream->bytes_left;
	stream->bytes_left = 0;

	if (response != TRANSACTION_NO_ERROR)
	{
		/* Transaction parse error. */
		writeFailureString(STRINGSET_TRANSACTION, (uint8_t)response);
		return true;
	}

	/* Get permission from user. */
	approved = false;

	/* Does transaction_hash match previous approved transaction? */
	if (prev_transaction_hash_valid)
	{
		if (bigCompare(transaction_hash, prev_transaction_hash) == BIGCMP_EQUAL)
			approved = true;
	}

	if (!approved)
	{
		/*
		 * Need to explicitly get permission from user.
		 * The call to parseTransaction() should have logged all the outputs
		 * to the user interface.
		 */
		permission_denied = buttonInterjection(ASKUSER_SIGN_TRANSACTION);

		if (!permission_denied)
		{
			/* User approved transaction. */
			approved = true;

			memcpy(prev_transaction_hash, transaction_hash, 32);

			prev_transaction_hash_valid = true;
		}
	}

	// if (approved)
	// {
	// 	/* Okay to sign transaction. */
	// 	signature_length = 0;

	// 	ah = sign_transaction.address_handle;

	// 	if (getPrivateKey(private_key, ah) == WALLET_NO_ERROR)
	// 	{
	// 		if (sizeof(message_buffer.signature_data.bytes) < MAX_SIGNATURE_LENGTH)
	// 			fatalError();	/* This should never happen. */

	// 		signTransaction(message_buffer.signature_data.bytes, &signature_length, sig_hash, private_key);

	// 		message_buffer.signature_data.size = signature_length;

	// 		sendPacket(PACKET_TYPE_SIGNATURE, Signature_fields, &message_buffer);
	// 	}
	// 	else
	// 	{
	// 		wallet_return = walletGetLastError();
	// 		translateWalletError(wallet_return);
	// 	}
	// }

	if (approved)
	{
		/* Okay to sign transaction. */
		signature_length = 0;

		ah = sign_transaction.address_handle;

		if (signTransaction2(message_buffer.signature_data.bytes, &signature_length, sig_hash, ah) == WALLET_NO_ERROR)
		{
			if (sizeof(message_buffer.signature_data.bytes) < MAX_SIGNATURE_LENGTH)
				fatalError();	/* This should never happen. */

			message_buffer.signature_data.size = signature_length;

			sendPacket(PACKET_TYPE_SIGNATURE, Signature_fields, &message_buffer);
		}
		else
		{
			wallet_return = walletGetLastError();
			translateWalletError(wallet_return);
		}
	}

	return true;
}

/** nanopb field callback which will write out the contents
  * of #entropy_buffer.
  * \param stream Output stream to write to.
  * \param field Field which contains the the entropy bytes.
  * \param arg Unused.
  * \return true on success, false on failure (nanopb convention).
  */
bool getEntropyCallback(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	if (entropy_buffer == NULL)
		return false;

	if (!pb_encode_tag_for_field(stream, field))
		return false;

	if (!pb_encode_string(stream, entropy_buffer, num_entropy_bytes))
		return false;

	return true;
}

/** Return bytes of entropy from the random number generation system.
  * \param num_bytes Number of bytes of entropy to send to stream.
  */
static NOINLINE void getBytesOfEntropy(uint32_t num_bytes)
{
	Entropy message_buffer;
	unsigned int random_bytes_index;
	uint8_t random_bytes[1024];	/* Must be multiple of 32 bytes large */

	if (num_bytes > sizeof(random_bytes))
	{
		writeFailureString(STRINGSET_MISC, MISCSTR_PARAM_TOO_LARGE);
		return;
	}

	/*
	 * All bytes of entropy must be collected before anything can be sent.
	 * This is because it is only safe to send those bytes if every call
	 * to getRandom256() succeeded.
	 */
	random_bytes_index = 0;

	num_entropy_bytes = 0;

	while (num_bytes--)
	{
		if (random_bytes_index == 0)
		{
			if (getRandom256(&(random_bytes[num_entropy_bytes])))
			{
				translateWalletError(WALLET_RNG_FAILURE);
				return;
			}
		}

		num_entropy_bytes++;
		random_bytes_index++;
		random_bytes_index &= 31;
	}

	message_buffer.entropy.funcs.encode = &getEntropyCallback;

	entropy_buffer = random_bytes;

	sendPacket(PACKET_TYPE_ENTROPY, Entropy_fields, &message_buffer);

	num_entropy_bytes = 0;

	entropy_buffer = NULL;
}

/** Send a packet containing an address and its corresponding public key.
  * This can generate new addresses as well as obtain old addresses. Both
  * use cases were combined into one function because they involve similar
  * processes.
  * \param generate_new If this is true, a new address will be generated
  *                     and the address handle of the generated address will
  *                     be prepended to the output packet.
  *                     If this is false, the address handle specified by ah
  *                     will be used.
  * \param ah Address handle to use (if generate_new is false).
  */
static NOINLINE void getAndSendAddressAndPublicKey(bool generate_new, AddressHandle ah)
{
	Address message_buffer;
	WalletErrors response;
	PointAffine public_key;

	message_buffer.address.size = 20;

	if (generate_new)
	{
		response = WALLET_NO_ERROR;

		ah = makeNewAddress(message_buffer.address.bytes, &public_key);

		if (ah == BAD_ADDRESS_HANDLE)
			response = walletGetLastError();
	}
	else
		response = getAddressAndPublicKey(message_buffer.address.bytes, &public_key, ah);

	if (response == WALLET_NO_ERROR)
	{
		message_buffer.address_handle = ah;

		if (sizeof(message_buffer.public_key.bytes) < ECDSA_MAX_SERIALISE_SIZE)	/* Sanity check */
		{
			fatalError();
			return;
		}

		message_buffer.public_key.size = ecdsaSerialiseTZ(message_buffer.public_key.bytes, &public_key, true);

		sendPacket(PACKET_TYPE_ADDRESS_PUBKEY, Address_fields, &message_buffer);
	}
	else
		translateWalletError(response);
}

/** Begin OtpRequest interjection. This asks the host to submit a one-time
  * password that is displayed on the device.
  * \return false if the host submitted a matching password, true on error.
  */
static bool otpInterjection(AskUserCommand command)
{
	char otp[OTP_LENGTH];
	OtpRequest  otp_request;
	OtpAck otp_ack;
	OtpCancel otp_cancel;
	uint16_t message_id;
	bool receive_failure;

	generateInsecureOTP(otp);

	if(is_test)
	{
		displayOTP(command, otp);
		memcpy(otp, test_otp, OTP_LENGTH);
	}

	displayOTP(command, otp);

	memset(&otp_request, 0, sizeof(otp_request));

	sendPacket(PACKET_TYPE_OTP_REQUEST, OtpRequest_fields, &otp_request);

	message_id = receivePacketHeader();

	clearOTP();

	if (message_id == PACKET_TYPE_OTP_ACK)
	{
		/* Host has just sent OTP */
		memset(&otp_ack, 0, sizeof(otp_ack));

		receive_failure =  receiveMessage(OtpAck_fields, &otp_ack);

		if (receive_failure)
			return true;
		else
		{
			if (memcmp(otp, otp_ack.otp, MIN(OTP_LENGTH, sizeof(otp_ack.otp))))
			{
				writeFailureString(STRINGSET_MISC, MISCSTR_OTP_MISMATCH);
				return true;
			}
			else
				return false;
		}
	}
	else if (message_id == PACKET_TYPE_OTP_CANCEL)
	{
		/* Host does not want to send OTP */
		receive_failure = receiveMessage(OtpCancel_fields, &otp_cancel);

		if (!receive_failure)
			writeFailureString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED_HOST);

		return true;
	}
	else
	{
		/* Unexpected message */
		readAndIgnoreInput();

		writeFailureString(STRINGSET_MISC, MISCSTR_UNEXPECTED_PACKET);

		return true;
	}
}

/** Begin PinRequest interjection. This asks the host to submit a password
  * to the device. If the host does submit a password, then #field_hash_set
  * will be set and #field_hash updated.
  * \return false if the host submitted a password, true on error.
  */
static bool pinInterjection(void)
{
	PinRequest pin_request;
	uint16_t message_id;
	PinAck pin_ack;
	bool receive_failure;
	PinCancel pin_cancel;

	memset(&pin_request, 0, sizeof(pin_request));

	sendPacket(PACKET_TYPE_PIN_REQUEST, PinRequest_fields, &pin_request);

	message_id = receivePacketHeader();

	if (message_id == PACKET_TYPE_PIN_ACK)
	{
		/* Host has just sent the password */
		field_hash_set = false;

		memset(field_hash, 0, sizeof(field_hash));

		pin_ack.password.funcs.decode = &hashFieldCallback;
		pin_ack.password.arg = NULL;

		receive_failure = receiveMessage(PinAck_fields, &pin_ack);

		if (receive_failure)
			return true;
		else
		{
			if (!field_hash_set)
				fatalError();	/* Should never happen since password is a required field*/

			return false;
		}
	}
	else if (message_id == PACKET_TYPE_PIN_CANCEL)
	{
		/* Host does not want to send the password */
		receive_failure = receiveMessage(PinCancel_fields, &pin_cancel);

		if (!receive_failure)
			writeFailureString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED_HOST);

		return true;
	}
	else
	{
		/* Unexpected message. */
		readAndIgnoreInput();

		writeFailureString(STRINGSET_MISC, MISCSTR_UNEXPECTED_PACKET);

		return true;
	}
}

/** Sends a Failure message with the specified error message.
  * \param set See getString().
  * \param spec See getString().
  */
static void writeFailureString(StringSet set, uint8_t spec)
{
	Failure message_buffer;
	uint32_t code;

	string_arg.next_set = set;
	string_arg.next_spec = spec;

	code = (uint32_t)spec & 0xffff;
	code |= ((uint32_t)set & 0xffff) << 16;

	message_buffer.error_code = code;
	message_buffer.error_message.funcs.encode = &writeStringCallback;
	message_buffer.error_message.arg = &string_arg;

	sendPacket(PACKET_TYPE_FAILURE, Failure_fields, &message_buffer);
}

/** Get packet from stream and deal with it. This basically implements the
  * protocol described in the file PROTOCOL.
  *
  * This function will always completely
  * read a packet before sending a response packet. As long as the host
  * does the same thing, deadlocks cannot occur. Thus a productive
  * communication session between the hardware Bitcoin wallet and a host
  * should consist of the wallet and host alternating between sending a
  * packet and receiving a packet.
  */
void processPacket(void)
{
	uint16_t message_id;
	union MessageBufferUnion message_buffer;
	bool receive_failure;
	bool has_ping_greeting;
	bool permission_denied;
	bool invalid_otp;
	char ping_greeting[sizeof(message_buffer.ping.greeting)];
	WalletErrors wallet_return;
	unsigned int password_length;
	PointAffine master_public_key;

	message_id = receivePacketHeader();

	/*
	 * Checklist for each case:
	 * 1. Have you checked or dealt with length?
	 * 2. Have you fully read the input stream before writing (to avoid
 	 *    deadlocks)?
 	 * 3. Have you asked permission from the user (for potentially dangerous
 	 *    operations)?
 	 * 4. Have you checked for errors from wallet functions?
 	 * 5. Have you used the right check for the wallet functions?
	 */

	memset(&message_buffer, 0, sizeof(message_buffer));

	switch (message_id)
	{
		/* Reset state and report features. */
		case PACKET_TYPE_INITIALIZE:

			session_id_length = 0; /* Just in case receiveMessage fails. */

			receive_failure = receiveMessage(Initialize_fields, &(message_buffer.initialize));

			if (!receive_failure)
			{
				session_id_length = message_buffer.initialize.session_id.size;

				if (session_id_length >= sizeof(session_id))
					fatalError(); /* Sanity check failed */

				memcpy(session_id, message_buffer.initialize.session_id.bytes, session_id_length);

				prev_transaction_hash_valid = false;

				sanitiseRam();

				wallet_return = uninitWallet();

				if (wallet_return == WALLET_NO_ERROR)
				{
					memset(&message_buffer, 0, sizeof(message_buffer));

					message_buffer.features.echoed_session_id.size = session_id_length;

					if (session_id_length >= sizeof(message_buffer.features.echoed_session_id.bytes))
						fatalError(); /* Sanity check failed */

					memcpy(message_buffer.features.echoed_session_id.bytes, session_id, session_id_length);

					string_arg.next_set = STRINGSET_MISC;
					string_arg.next_spec = MISCSTR_VENDOR;

					message_buffer.features.vendor.funcs.encode = &writeStringCallback;
					message_buffer.features.vendor.arg = &string_arg;
					message_buffer.features.has_major_version = true;
					message_buffer.features.major_version = VERSION_MAJOR;
					message_buffer.features.has_minor_version = true;
					message_buffer.features.minor_version = VERSION_MINOR;
					string_arg_alt.next_set = STRINGSET_MISC;
					string_arg_alt.next_spec = MISCSTR_CONFIG;
					message_buffer.features.config.funcs.encode = &writeStringCallback;
					message_buffer.features.config.arg = &string_arg_alt;
					message_buffer.features.has_otp = true;
					message_buffer.features.otp = true;
					message_buffer.features.has_pin = true;
					message_buffer.features.pin = true;
					message_buffer.features.has_spv = true;
					message_buffer.features.spv = true;
					message_buffer.features.algo_count = 1;
					message_buffer.features.algo[0] = Algorithm_BIP32;
					message_buffer.features.has_debug_link = true;
					message_buffer.features.debug_link = false;
					sendPacket(PACKET_TYPE_FEATURES, Features_fields, &(message_buffer.features));
				}
				else
					translateWalletError(wallet_return);
			}

			break;

		/* Ping request */
		case PACKET_TYPE_PING:

			receive_failure = receiveMessage(Ping_fields, &(message_buffer.ping));

			if (!receive_failure)
			{
				has_ping_greeting = message_buffer.ping.has_greeting;

				if (sizeof(message_buffer.ping.greeting) != sizeof(ping_greeting))
					fatalError();	/* Sanity check failed */

				if (has_ping_greeting)
					memcpy(ping_greeting, message_buffer.ping.greeting, sizeof(ping_greeting));

				ping_greeting[sizeof(ping_greeting) - 1] = '\0';	/* Ensure that string is terminated */

				/* Generate ping response message. */
				memset(&message_buffer, 0, sizeof(message_buffer));

				message_buffer.ping_response.has_echoed_greeting = has_ping_greeting;

				if (sizeof(ping_greeting) != sizeof(message_buffer.ping_response.echoed_greeting))
					fatalError();	/* Sanity check failed */

				if (has_ping_greeting)
					memcpy(message_buffer.ping_response.echoed_greeting, ping_greeting, sizeof(message_buffer.ping_response.echoed_greeting));

				message_buffer.ping_response.echoed_session_id.size = session_id_length;

				if (session_id_length >= sizeof(message_buffer.ping_response.echoed_session_id.bytes))
					fatalError();	/* Sanity check failed */

				memcpy(message_buffer.ping_response.echoed_session_id.bytes, session_id, session_id_length);

				sendPacket(PACKET_TYPE_PING_RESPONSE, PingResponse_fields, &(message_buffer.ping_response));
			}

			break;

		/* Delete existing wallet */
		case PACKET_TYPE_DELETE_WALLET:

			receive_failure = receiveMessage(DeleteWallet_fields, &(message_buffer.delete_wallet));

			if (!receive_failure)
			{
				permission_denied = buttonInterjection(ASKUSER_DELETE_WALLET);

				if (!permission_denied)
				{
					invalid_otp = otpInterjection(ASKUSER_DELETE_WALLET);

					if (!invalid_otp)
					{
						wallet_return = deleteWallet(message_buffer.delete_wallet.wallet_handle);
						translateWalletError(wallet_return);
					}
				}
			}

			break;

		/* Create new wallet */
		case PACKET_TYPE_NEW_WALLET:

			field_hash_set = false;

			memset(field_hash, 0, sizeof(field_hash));

			message_buffer.new_wallet.password.funcs.decode = &hashFieldCallback;
			message_buffer.new_wallet.password.arg = NULL;

			receive_failure = receiveMessage(NewWallet_fields, &(message_buffer.new_wallet));

			if (!receive_failure)
			{
				permission_denied = buttonInterjection(ASKUSER_NEW_WALLET);

				if (!permission_denied)
				{
					if (field_hash_set)
						password_length = sizeof(field_hash);
					else
						password_length = 0;	/* No password */

					wallet_return =  newWallet(
										message_buffer.new_wallet.wallet_number,
										message_buffer.new_wallet.wallet_name.bytes,
										false,
										NULL,
										message_buffer.new_wallet.is_hidden,
										field_hash,
										password_length);

					translateWalletError(wallet_return);
				}
			}

			break;

		/* Create a new address in the wallet */
		case PACKET_TYPE_NEW_ADDRESS:

			receive_failure = receiveMessage(NewAddress_fields, &(message_buffer.new_address));

			if (!receive_failure)
			{
				permission_denied = buttonInterjection(ASKUSER_NEW_ADDRESS);

				if (!permission_denied)
					getAndSendAddressAndPublicKey(true, BAD_ADDRESS_HANDLE);
			}

			break;

		/* Get number of addresses in wallet. */
		case PACKET_TYPE_GET_NUM_ADDRESSES:

			receive_failure = receiveMessage(GetNumberOfAddresses_fields, &(message_buffer.get_number_of_addresses));

			if (!receive_failure)
			{
				message_buffer.number_of_addresses.number_of_addresses = getNumAddresses();

				wallet_return = walletGetLastError();

				if (wallet_return == WALLET_NO_ERROR)
					sendPacket(PACKET_TYPE_NUM_ADDRESSES, NumberOfAddresses_fields, &(message_buffer.number_of_addresses));
				else
					translateWalletError(wallet_return);
			}

			break;

		/* Get address and public key corresponding to an address handle. */
		case PACKET_TYPE_GET_ADDRESS_PUBKEY:

			receive_failure = receiveMessage(GetAddressAndPublicKey_fields, &(message_buffer.get_address_and_public_key));

			if (!receive_failure)
				getAndSendAddressAndPublicKey(false, message_buffer.get_address_and_public_key.address_handle);

			break;

		case PACKET_TYPE_SIGN_TRANSACTION:

			/* Sign a transaction. */
			sign_transaction.transaction_data.funcs.decode = &signTransactionCallback;

			/* Everything else is handled in signTransactionCallback(). */
			receiveMessage(SignTransaction_fields, &sign_transaction);

			break;

		/* Load wallet */
		case PACKET_TYPE_LOAD_WALLET:

			receive_failure = receiveMessage(LoadWallet_fields, &(message_buffer.load_wallet));

			if (!receive_failure)
			{
				/* Attempt to load without password */
				wallet_return = initWallet(message_buffer.load_wallet.wallet_number, field_hash, 0);

				if (wallet_return == WALLET_NOT_THERE)
				{
					/* Attempt to load with password */
					permission_denied = pinInterjection();

					if (!permission_denied)
					{
						if (!field_hash_set)
							fatalError(); 	/* This should never happen */

						wallet_return = initWallet(message_buffer.load_wallet.wallet_number, field_hash, sizeof(field_hash));

						translateWalletError(wallet_return);
					}
				}
				else
					translateWalletError(wallet_return);
			}

			break;

		/* Format storage. */
		case PACKET_TYPE_FORMAT:

			receive_failure = receiveMessage(FormatWalletArea_fields, &(message_buffer.format_wallet_area));

			if (!receive_failure)
			{
				permission_denied = buttonInterjection(ASKUSER_FORMAT);

				if (!permission_denied)
				{
					invalid_otp = otpInterjection(ASKUSER_FORMAT);

					if (!invalid_otp)
					{
						if (initialiseEntropyPool(message_buffer.format_wallet_area.initial_entropy_pool.bytes))
							translateWalletError(WALLET_RNG_FAILURE);
						else
						{
							wallet_return = sanitiseEverything();
							translateWalletError(wallet_return);
							uninitWallet(); /* Force wallet to unload */
						}
					}
				}
			}

			break;

		/* Change wallet encryption key */
		case PACKET_TYPE_CHANGE_KEY:

			field_hash_set = false;

			memset(field_hash, 0, sizeof(field_hash));

			message_buffer.change_encryption_key.password.funcs.decode = &hashFieldCallback;
			message_buffer.change_encryption_key.password.arg = NULL;

			receive_failure = receiveMessage(ChangeEncryptionKey_fields, &(message_buffer.change_encryption_key));

			if (!receive_failure)
			{
				permission_denied = buttonInterjection(ASKUSER_CHANGE_KEY);

				if (!permission_denied)
				{
					invalid_otp = otpInterjection(ASKUSER_CHANGE_KEY);

					if (!invalid_otp)
					{
						if (field_hash_set)
							password_length = sizeof(field_hash);
						else
							password_length = 0;	/* No password */

						wallet_return = changeEncryptionKey(field_hash, password_length);

						translateWalletError(wallet_return);
					}
				}
			}

			break;

		/* Change wallet name */
		case PACKET_TYPE_CHANGE_NAME:

			receive_failure = receiveMessage(ChangeWalletName_fields, &(message_buffer.change_wallet_name));

			if (!receive_failure)
			{
				permission_denied = buttonInterjection(ASKUSER_CHANGE_NAME);

				if (!permission_denied)
				{
					wallet_return = changeWalletName(message_buffer.change_wallet_name.wallet_name.bytes);
					translateWalletError(wallet_return);
				}
			}

			break;

		/* List wallets */
		case PACKET_TYPE_LIST_WALLETS:

			receive_failure = receiveMessage(ListWallets_fields, &(message_buffer.list_wallets));

			if (!receive_failure)
			{
				number_of_wallets = getNumberOfWallets();

				if(number_of_wallets == 0)
				{
					wallet_return = walletGetLastError();
					translateWalletError(wallet_return);
				}
				else
				{
					message_buffer.wallets.wallet_info.funcs.encode = &listWalletsCallback;
					sendPacket(PACKET_TYPE_WALLETS, Wallets_fields, &(message_buffer.wallets));
				}
			}

			break;

		/* Backup wallet */
		case PACKET_TYPE_BACKUP_WALLET:

			receive_failure = receiveMessage(BackupWallet_fields, &(message_buffer.backup_wallet));

			if (!receive_failure)
			{
				permission_denied = buttonInterjection(ASKUSER_BACKUP_WALLET);

				if (!permission_denied)
				{
					wallet_return = backupWallet(message_buffer.backup_wallet.is_encrypted, message_buffer.backup_wallet.device);
					translateWalletError(wallet_return);
				}
			}

			break;

		/* Restore wallet */
		case PACKET_TYPE_RESTORE_WALLET:

			field_hash_set = false;

			memset(field_hash, 0, sizeof(field_hash));

			message_buffer.restore_wallet.new_wallet.password.funcs.decode = &hashFieldCallback;

			message_buffer.restore_wallet.new_wallet.password.arg = NULL;

			receive_failure = receiveMessage(RestoreWallet_fields, &(message_buffer.restore_wallet));

			if (!receive_failure)
			{
				if (message_buffer.restore_wallet.seed.size != SEED_LENGTH)
					writeFailureString(STRINGSET_MISC, MISCSTR_INVALID_PACKET);
				else
				{
					permission_denied = buttonInterjection(ASKUSER_RESTORE_WALLET);

					if (!permission_denied)
					{
						if (field_hash_set)
							password_length = sizeof(field_hash);
						else
							password_length = 0;	/* No password */

						wallet_return = newWallet(
							message_buffer.restore_wallet.new_wallet.wallet_number,
							message_buffer.restore_wallet.new_wallet.wallet_name.bytes,
							true,
							message_buffer.restore_wallet.seed.bytes,
							message_buffer.restore_wallet.new_wallet.is_hidden,
							field_hash,
							password_length);

						translateWalletError(wallet_return);
					}
				}
			}

			break;

		/* Get device UUID */
		case PACKET_TYPE_GET_DEVICE_UUID:

			receive_failure = receiveMessage(GetDeviceUUID_fields, &(message_buffer.get_device_uuid));

			if (!receive_failure)
			{
				message_buffer.device_uuid.device_uuid.size = UUID_LENGTH;

				if (nonVolatileRead(message_buffer.device_uuid.device_uuid.bytes, PARTITION_GLOBAL, ADDRESS_DEVICE_UUID, UUID_LENGTH) == NV_NO_ERROR)
					sendPacket(PACKET_TYPE_DEVICE_UUID, DeviceUUID_fields, &(message_buffer.device_uuid));
				else
					translateWalletError(WALLET_READ_ERROR);
			}

			break;

		/* Get an arbitrary number of bytes of entropy. */
		case PACKET_TYPE_GET_ENTROPY:

			receive_failure = receiveMessage(GetEntropy_fields, &(message_buffer.get_entropy));

			if (!receive_failure)
				getBytesOfEntropy(message_buffer.get_entropy.number_of_bytes);

			break;

		/* Get master public key and chain code. */
		case PACKET_TYPE_GET_MASTER_KEY:

			receive_failure = receiveMessage(GetMasterPublicKey_fields, &(message_buffer.get_master_public_key));

			if (!receive_failure)
			{
				permission_denied = buttonInterjection(ASKUSER_GET_MASTER_KEY);

				if (!permission_denied)
				{
					invalid_otp = otpInterjection(ASKUSER_GET_MASTER_KEY);

					if (!invalid_otp)
					{
						wallet_return = getMasterPublicKey(&master_public_key, message_buffer.master_public_key.chain_code.bytes);

						if (wallet_return == WALLET_NO_ERROR)
						{
							message_buffer.master_public_key.chain_code.size = 32;

							if (sizeof(message_buffer.master_public_key.public_key.bytes) < ECDSA_MAX_SERIALISE_SIZE) // sanity check
							{
								fatalError();
								return;
							}

							message_buffer.master_public_key.public_key.size = ecdsaSerialiseTZ(message_buffer.master_public_key.public_key.bytes, &master_public_key, true);

							sendPacket(PACKET_TYPE_MASTER_KEY, MasterPublicKey_fields, &(message_buffer.master_public_key));
						}
						else
							translateWalletError(wallet_return);
					}
				}
			}

			break;

		/* Unknown message ID. */
		default:
			readAndIgnoreInput();
			writeFailureString(STRINGSET_MISC, MISCSTR_UNEXPECTED_PACKET);
			break;
	}
}
