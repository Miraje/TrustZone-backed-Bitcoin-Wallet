/** \file
  *
  * \brief Implements the user interface.
  *
  * This file should contain user interface components which are not specific
  * to any display controller. For example, things like the contents and
  * formatting of each text prompt.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "extern.h"
#include "hwinterface.h"
#include "prandom.h"
#include "user_interface.h"

#include <stdio.h>
#include <stdlib.h>

/** Storage for the text of transaction output amounts. */
static char amount_list[MAX_OUTPUTS_RAM][TEXT_AMOUNT_LENGTH];

/** Storage for the text of transaction output addresses. */
static char address_list[MAX_OUTPUTS_RAM][TEXT_ADDRESS_LENGTH];

/** Whether the transaction fee has been set. If
  * the transaction fee still hasn't been set after parsing, then the
  * transaction is free. */
static bool transaction_fee_set;

/** Storage for transaction fee amount. This is only valid
  * if #transaction_fee_set is true. */
static char transaction_fee_amount[TEXT_AMOUNT_LENGTH];

/** This will be called whenever something very unexpected occurs. This
  * function must not return. */
void fatalError(void)
{
	printf("****************\n");
	printf("* FATAL ERROR! *\n");
	printf("****************\n");

	exit(1);
}

/** Notify the user interface that the transaction parser has seen a new
  * Bitcoin amount/address pair.
  * \param text_amount The output amount, as a null-terminated text string
  *                    such as "0.01".
  * \param text_address The output address, as a null-terminated text string
  *                     such as "1RaTTuSEN7jJUDiW1EGogHwtek7g9BiEn".
  * \return false if no error occurred, true if there was not enough space to
  *         store the amount/address pair.
  */
bool newOutputSeen(char *text_amount, char *text_address)
{
    char *amount_dest;
    char *address_dest;

    /* not enough space to store the amount/address pair */
    if (num_outputs_seen >= MAX_OUTPUTS_RAM)
        return true;

    amount_dest = amount_list[num_outputs_seen];
    address_dest = address_list[num_outputs_seen];

    strncpy(amount_dest, text_amount, TEXT_AMOUNT_LENGTH);
    strncpy(address_dest, text_address, TEXT_ADDRESS_LENGTH);

    printf("\n");
    printf("Amount: %s\n", text_amount);
    printf("Address: %s\n", text_address);
    printf("\n");

    num_outputs_seen++;

    return false; /* Success */
}

/** Notify the user interface that the transaction parser has seen the
  * transaction fee. If there is no transaction fee, the transaction parser
  * will not call this.
  * \param text_amount The transaction fee, as a null-terminated text string
  *                    such as "0.01".
  */
void setTransactionFee(char *text_amount)
{
    strncpy(transaction_fee_amount, text_amount, TEXT_AMOUNT_LENGTH);
    transaction_fee_set = true;
    printf("Transaction fee: %s\n", text_amount);
}

/** Notify the user interface that the list of Bitcoin amount/address pairs
  * should be cleared. */
void clearOutputsSeen(void)
{
    num_outputs_seen = 0;
    transaction_fee_set = false;
}

/** Write backup seed to some output device. The choice of output device and
  * seed representation is up to the platform-dependent code. But a typical
  * example would be displaying the seed as a hexadecimal string on a LCD.
  * \param seed A byte array of length #SEED_LENGTH bytes which contains the
  *             backup seed.
  * \param is_encrypted Specifies whether the seed has been encrypted.
  * \param destination_device Specifies which (platform-dependent) device the
  *                           backup seed should be sent to.
  * \return false on success, true if the backup seed could not be written
  *         to the destination device.
  */
bool writeBackupSeed(uint8_t *seed, bool is_encrypted, uint32_t destination_device)
{
    int i;
    int byte_counter;

    if (destination_device != 0)
        return true;
    else
    {
        if (is_encrypted)
            printf("\nThe seed is encrypted\n");
        else
            printf("\nThe seed is unencrypted\n");

        printf("\n");

        byte_counter = 0;

        printf("Wallet seed:\n\n");

        /*
         * The following code will output the seed in the format:
         * " xxxx xxxx xxxx xxxx"
         * " xxxx xxxx xxxx xxxx"
         */
        for (i = 0; i < SEED_LENGTH; i++)
        {
            if (byte_counter == 2 || byte_counter == 4 || byte_counter == 6)
                printf(" ");

            if (byte_counter == 8)
            {
                byte_counter = 0;
                printf("\n");
            }

            printf("%02x", seed[i]);

            byte_counter++;
        }

        printf("\n\n");

        if(is_test)
            memcpy(test_wallet_backup, seed, SEED_LENGTH);

        return false;
    }
}

/** Display human-readable description of an action on stdout.
  * \param command The action to display. See #AskUserCommandEnum.
  * \return printed string of the action description
  */
static void printAction(AskUserCommand command)
{
    printf("\n");

    switch (command)
    {
        case ASKUSER_NEW_WALLET:
            printf("Create new wallet? ");
            break;
        case ASKUSER_NEW_ADDRESS:
            printf("Create new address? ");
            break;
        case ASKUSER_SIGN_TRANSACTION:
            printf("Sign transaction? ");
            break;
        case ASKUSER_FORMAT:
            printf("Format storage area? ");
            break;
        case ASKUSER_CHANGE_NAME:
            printf("Change wallet name? ");
            break;
        case ASKUSER_BACKUP_WALLET:
            printf("Do a wallet backup? ");
            break;
        case ASKUSER_RESTORE_WALLET:
            printf("Restore wallet from backup? ");
            break;
        case ASKUSER_CHANGE_KEY:
            printf("Change wallet encryption key? ");
            break;
        case ASKUSER_GET_MASTER_KEY:
            printf("Reveal master public key? ");
            break;
        case ASKUSER_DELETE_WALLET:
            printf("Delete existing wallet? ");
            break;
        default:
            printf("Invalid user command!\n");
            /* fatalError(); */                     /* IS IT NEEDED? */
    }
}

/** Get the user confirmation to a action.
  * \return false if the user accepted, true if the user denied.
  */
bool getUserConfirmation(void)
{
    int ch;

    printf("\n");
    printf("y/[n]: ");

    if (is_test_stream)
      return false;

    do
    {
        ch = getchar();
    }
    while ((ch == '\n') || (ch == '\r'));

    if ((ch == 'y') || (ch == 'Y'))
        return false;
    else
        return true;
}

/** Ask user if they want to allow some action.
  * \param command The action to ask the user about. See #AskUserCommandEnum.
  * \return false if the user accepted, true if the user denied.
  */
bool userDenied(AskUserCommand command)
{
    int i;
    bool response = true;

    printf("\n");

    switch(command)
    {
        case ASKUSER_NEW_WALLET:
        case ASKUSER_NEW_ADDRESS:
        case ASKUSER_CHANGE_NAME:
        case ASKUSER_BACKUP_WALLET:
        case ASKUSER_RESTORE_WALLET:
        case ASKUSER_CHANGE_KEY:
        case ASKUSER_GET_MASTER_KEY:
        case ASKUSER_DELETE_WALLET:
            printAction(command);
            return getUserConfirmation();
            break;

        case ASKUSER_SIGN_TRANSACTION:
            for (i = 0; i < num_outputs_seen; i++)
            {
                printf("Send ");
                printf("%s", amount_list[i]);
                printf(" BTC to ");
                printf("%s", address_list[i]);
                printf("? ");
                response = getUserConfirmation();

                if (response)
                {
                    /*
                    All outputs must be approved in order for a transaction
                    to be signed. Thus if the user denies spending to one
                    output, the entire transaction is forfeit.
                    */
                    break;
                }
            }

            if (!response && transaction_fee_set)                       /* JUST ONE TRANSACTION FEE FOR ALL THE TRANSACTIONS? */
            {
                printf("Transaction fee: ");
                printf("%s", transaction_fee_amount);
                printf("BTC.\n");
                printf("Is this okay? ");
                response = getUserConfirmation();
            }

            break;

        case ASKUSER_FORMAT:
            printf("Format storage? This will delete everything!");
            response = getUserConfirmation();

            if (!response)
            {
                printf("Are you sure you you want to nuke all wallets?");
                response = getUserConfirmation();

                if (!response)
                {
                    printf("Are you really really sure?");
                    response = getUserConfirmation();
                }
            }

            break;

        default:
            printf("Unknown command in userDenied().\n");
            response = true;
            break;
    }

    return response;
}

/** Display a short (maximum 8 characters) one-time password for the user to
  * see. This one-time password is used to reduce the chance of a user
  * accidentally doing something stupid.
  * \param command The action to ask the user about. See #AskUserCommandEnum.
  * \param otp The one-time password to display. This will be a
  *            null-terminated string.
  */
void displayOTP(AskUserCommand command, char *otp)
{
    printAction(command);
    printf("OTP: %s\n", otp);
}

/** Clear the OTP (one-time password) shown by displayOTP() from the
  * display. */
void clearOTP(void)
{
    /* Nothing to do */
}
