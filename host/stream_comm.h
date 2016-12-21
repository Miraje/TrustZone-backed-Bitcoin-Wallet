/** \file
  *
  * \brief Describes functions, types and constants exported by stream_comm.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef STREAM_COMM_H_INCLUDED
#define STREAM_COMM_H_INCLUDED

/** Major version number to report to the host. */
#define VERSION_MAJOR					1
/** Minor version number to report to the host. */
#define VERSION_MINOR					0

#include "common.h"
#include "hwinterface.h"
#include "messages.pb.h"
#include "pb.h"
#include "pb_decode.h"
#include "pb_encode.h"

/** Union of field buffers for all protocol buffer messages. They're placed
  * in a union to make memory access more efficient, since the functions in
  * this file only need to deal with one message at any one time. */
union MessageBufferUnion
{
  Initialize initialize;
  Features features;
  Ping ping;
  PingResponse ping_response;
  DeleteWallet delete_wallet;
  NewWallet new_wallet;
  NewAddress new_address;
  GetNumberOfAddresses get_number_of_addresses;
  NumberOfAddresses number_of_addresses;
  GetAddressAndPublicKey get_address_and_public_key;
  LoadWallet load_wallet;
  FormatWalletArea format_wallet_area;
  ChangeEncryptionKey change_encryption_key;
  ChangeWalletName change_wallet_name;
  ListWallets list_wallets;
  Wallets wallets;
  BackupWallet backup_wallet;
  RestoreWallet restore_wallet;
  GetDeviceUUID get_device_uuid;
  DeviceUUID device_uuid;
  GetEntropy get_entropy;
  GetMasterPublicKey get_master_public_key;
  MasterPublicKey master_public_key;
};

/** Determines the string that writeStringCallback() will write. */
struct StringSetAndSpec
{
  /** String set (see getString()) of string to be outputted. */
  StringSet next_set;
  /** String specifier (see getString()) of string to be outputted. */
  uint8_t next_spec;
};

/**
 * \defgroup DeviceStrings Device-specific strings.
 *
 * @{
 */
/** Vendor string. */
static const char str_MISCSTR_VENDOR[] = "Miraje Limited";
/** Permission denied (user pressed cancel button) string. */
static const char str_MISCSTR_PERMISSION_DENIED_USER[] = "Permission denied by user";
/** String specifying that processPacket() didn't like the format or
  * contents of a packet. */
static const char str_MISCSTR_INVALID_PACKET[] = "Invalid packet";
/** String specifying that a parameter was unacceptably large. */
static const char str_MISCSTR_PARAM_TOO_LARGE[] = "Parameter too large";
/** Permission denied (host cancelled action) string. */
static const char str_MISCSTR_PERMISSION_DENIED_HOST[] = "Host cancelled action";
/** String specifying that an unexpected message was received. */
static const char str_MISCSTR_UNEXPECTED_PACKET[] = "Unexpected packet";
/** String specifying that the submitted one-time password (OTP) did not match
  * the generated OTP. */
static const char str_MISCSTR_OTP_MISMATCH[] = "OTP mismatch";
/** Configuration string. */
static const char str_MISCSTR_CONFIG[] = "Configured for Juno-r2 by Miraje";
/** String for #WALLET_FULL wallet error. */
static const char str_WALLET_FULL[] = "Wallet has run out of space";
/** String for #WALLET_EMPTY wallet error. */
static const char str_WALLET_EMPTY[] = "Wallet has nothing in it";
/** String for #WALLET_READ_ERROR wallet error. */
static const char str_WALLET_READ_ERROR[] = "Flash memory read error";
/** String for #WALLET_WRITE_ERROR error. */
static const char str_WALLET_WRITE_ERROR[] = "Flash memory write error";
/** String for #WALLET_NOT_THERE wallet error. */
static const char str_WALLET_NOT_THERE[] = "Wallet doesn't exist";
/** String for #WALLET_NOT_LOADED wallet error. */
static const char str_WALLET_NOT_LOADED[] = "Wallet not loaded";
/** String for #WALLET_INVALID_HANDLE wallet error. */
static const char str_WALLET_INVALID_HANDLE[] = "Invalid address handle";
/** String for #WALLET_BACKUP_ERROR wallet error. */
static const char str_WALLET_BACKUP_ERROR[] = "Seed could not be written to specified device";
/** String for #WALLET_RNG_FAILURE wallet error. */
static const char str_WALLET_RNG_FAILURE[] = "Failure in random number generation system";
/** String for #WALLET_INVALID_WALLET_NUM wallet error. */
static const char str_WALLET_INVALID_WALLET_NUM[] = "Invalid wallet number";
/** String for #WALLET_INVALID_OPERATION wallet error. */
static const char str_WALLET_INVALID_OPERATION[] = "Operation not allowed";
/** String for #WALLET_ALREADY_EXISTS wallet error. */
static const char str_WALLET_ALREADY_EXISTS[] = "Wallet already exists";
/** String for #WALLET_BAD_ADDRESS wallet error. */
static const char str_WALLET_BAD_ADDRESS[] = "Bad non-volatile storage address or partition number";
/** String for #TRANSACTION_INVALID_FORMAT transaction parser error. */
static const char str_TRANSACTION_INVALID_FORMAT[] = "Format of transaction is unknown or invalid";
/** String for #TRANSACTION_TOO_MANY_INPUTS transaction parser error. */
static const char str_TRANSACTION_TOO_MANY_INPUTS[] = "Too many inputs in transaction";
/** String for #TRANSACTION_TOO_MANY_OUTPUTS transaction parser error. */
static const char str_TRANSACTION_TOO_MANY_OUTPUTS[] = "Too many outputs in transaction";
/** String for #TRANSACTION_TOO_LARGE transaction parser error. */
static const char str_TRANSACTION_TOO_LARGE[] = "Transaction's size is too large";
/** String for #TRANSACTION_NON_STANDARD transaction parser error. */
static const char str_TRANSACTION_NON_STANDARD[] = "Transaction is non-standard";
/** String for #TRANSACTION_INVALID_AMOUNT transaction parser error. */
static const char str_TRANSACTION_INVALID_AMOUNT[] = "Invalid output amount in transaction";
/** String for #TRANSACTION_INVALID_REFERENCE transaction parser error. */
static const char str_TRANSACTION_INVALID_REFERENCE[] = "Invalid transaction reference";
/** String for unknown error. */
static const char str_UNKNOWN[] = "Unknown error";
/**@}*/

/**
 * \defgroup PacketTypes Type values for packets.
 *
 * See the file PROTOCOL for more information about the format of packets
 * and what the payload of packets should be.
 *
 * @{
 */
/** Request a response from the wallet. */
#define PACKET_TYPE_PING				0x00
/** Create a new wallet. */
#define PACKET_TYPE_NEW_WALLET			0x04
/** Create a new address in a wallet. */
#define PACKET_TYPE_NEW_ADDRESS			0x05
/** Get number of addresses in a wallet. */
#define PACKET_TYPE_GET_NUM_ADDRESSES	0x06
/** Get an address and its associated public key from a wallet. */
#define PACKET_TYPE_GET_ADDRESS_PUBKEY	0x09
/** Sign a transaction. */
#define PACKET_TYPE_SIGN_TRANSACTION	0x0A
/** Load (unlock) a wallet. */
#define PACKET_TYPE_LOAD_WALLET			0x0B
/** Format storage area, erasing everything. */
#define PACKET_TYPE_FORMAT				0x0D
/** Change encryption key of a wallet. */
#define PACKET_TYPE_CHANGE_KEY			0x0E
/** Change name of a wallet. */
#define PACKET_TYPE_CHANGE_NAME			0x0F
/** List all wallets. */
#define PACKET_TYPE_LIST_WALLETS		0x10
/** Backup a wallet. */
#define PACKET_TYPE_BACKUP_WALLET		0x11
/** Restore wallet from a backup. */
#define PACKET_TYPE_RESTORE_WALLET		0x12
/** Get device UUID. */
#define PACKET_TYPE_GET_DEVICE_UUID		0x13
/** Get bytes of entropy. */
#define PACKET_TYPE_GET_ENTROPY			0x14
/** Get master public key. */
#define PACKET_TYPE_GET_MASTER_KEY		0x15
/** Delete a wallet. */
#define PACKET_TYPE_DELETE_WALLET		0x16
/** Initialise device's state. */
#define PACKET_TYPE_INITIALIZE			0x17
/** An address from a wallet (response to #PACKET_TYPE_GET_ADDRESS_PUBKEY
  * or #PACKET_TYPE_NEW_ADDRESS). */
#define PACKET_TYPE_ADDRESS_PUBKEY		0x30
/** Number of addresses in a wallet
  * (response to #PACKET_TYPE_GET_NUM_ADDRESSES). */
#define PACKET_TYPE_NUM_ADDRESSES		0x31
/** Public information about all wallets
  * (response to #PACKET_TYPE_LIST_WALLETS). */
#define PACKET_TYPE_WALLETS				0x32
/** Wallet's response to ping (see #PACKET_TYPE_PING). */
#define PACKET_TYPE_PING_RESPONSE		0x33
/** Packet signifying successful completion of an operation. */
#define PACKET_TYPE_SUCCESS				0x34
/** Packet signifying failure of an operation. */
#define PACKET_TYPE_FAILURE				0x35
/** Device UUID (response to #PACKET_TYPE_GET_DEVICE_UUID). */
#define PACKET_TYPE_DEVICE_UUID			0x36
/** Some bytes of entropy (response to #PACKET_TYPE_GET_ENTROPY). */
#define PACKET_TYPE_ENTROPY				0x37
/** Master public key (response to #PACKET_TYPE_GET_MASTER_KEY). */
#define PACKET_TYPE_MASTER_KEY			0x38
/** Signature (response to #PACKET_TYPE_SIGN_TRANSACTION). */
#define PACKET_TYPE_SIGNATURE			0x39
/** Version information and list of features. */
#define PACKET_TYPE_FEATURES			0x3a
/** Device wants to wait for button press (beginning of ButtonRequest
  * interjection). */
#define PACKET_TYPE_BUTTON_REQUEST		0x50
/** Host will allow button press (response to #PACKET_TYPE_BUTTON_REQUEST). */
#define PACKET_TYPE_BUTTON_ACK			0x51
/** Host will not allow button press (response
  * to #PACKET_TYPE_BUTTON_REQUEST). */
#define PACKET_TYPE_BUTTON_CANCEL		0x52
/** Device wants host to send a password (beginning of PinRequest
  * interjection. */
#define PACKET_TYPE_PIN_REQUEST			0x53
/** Host sends password (response to #PACKET_TYPE_PIN_REQUEST). */
#define PACKET_TYPE_PIN_ACK				0x54
/** Host does not want to send password (response
  * to #PACKET_TYPE_PIN_REQUEST). */
#define PACKET_TYPE_PIN_CANCEL			0x55
/** Device wants host to send a one-time password (beginning of OtpRequest
  * interjection. */
#define PACKET_TYPE_OTP_REQUEST			0x56
/** Host sends one-time password (response to #PACKET_TYPE_OTP_REQUEST). */
#define PACKET_TYPE_OTP_ACK				0x57
/** Host does not want to send one-time password (response
  * to #PACKET_TYPE_OTP_REQUEST). */
#define PACKET_TYPE_OTP_CANCEL			0x58
/**@}*/

/** Maximum size (in bytes) of any protocol buffer message sent by functions
  * in this file. */
#define MAX_SEND_SIZE			        255

uint16_t getStringLength(StringSet set, uint8_t spec);
char getString(StringSet set, uint8_t spec, uint16_t pos);
void setTestInputStream(const uint8_t *buffer, uint32_t length);
void setInfiniteZeroInputStream(void);
uint8_t streamGetOneByte(void);
void streamGetBytes(uint8_t * out, uint8_t length);
void processPacket(void);

#endif /* #ifndef STREAM_COMM_H_INCLUDED */