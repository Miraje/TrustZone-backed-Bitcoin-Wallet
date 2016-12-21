/** \file
  *
  * \brief Describes functions, types and constants exported by user_interface.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef USER_INTERFACE_H_INCLUDED
#define USER_INTERFACE_H_INCLUDED

/** Maximum number of address/amount pairs that can be stored in RAM waiting
  * for approval from the user.
  * \warning This incidentally sets the maximum number of outputs per transaction
  * that parseTransaction() can deal with. To avoid problems during testing it
  * should have the same value as #MAX_OUTPUTS .
  */
#define MAX_OUTPUTS_RAM		2000

/** Required size of a buffer which stores the text of a transaction output
  * amount. This includes the terminating null. */
#define TEXT_AMOUNT_LENGTH	22

/** Required size of a buffer which stores the text of a transaction output
  * address. This includes the terminating null. */
#define TEXT_ADDRESS_LENGTH	36

bool newOutputSeen(char *text_amount, char *text_address);
bool userDenied(AskUserCommand command);
bool writeBackupSeed(uint8_t *seed, bool is_encrypted, uint32_t destination_device);
bool writeBackupSeed(uint8_t *seed, bool is_encrypted, uint32_t destination_device);
void clearOTP(void);
void clearOutputsSeen(void);
void displayOTP(AskUserCommand command, char *otp);
void fatalError(void);
void setTransactionFee(char *text_amount);

#endif /* #ifndef USER_INTERFACE_H_INCLUDED */