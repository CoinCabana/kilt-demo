import {Keyring} from "@kiltprotocol/utils";

class AccountFactory {

    createAccount(mnemonic: string) {
        const keyring = new Keyring({ ss58Format: 38, type: 'sr25519'});
        return keyring.addFromMnemonic(mnemonic);
    }
}

export const accountFactory = new AccountFactory();