import {Keyring} from "@kiltprotocol/utils";

class AccountFactory {

    createAccount(mnemonic: string) {
        const keyring = new Keyring({ ss58Format: 38, type: 'sr25519'});
        const test = new Keyring({  type: 'ethereum'});
        const kr = test.addFromMnemonic(mnemonic)
        console.log(kr.address, Buffer.from(kr.publicKey).toString('hex'))
        return keyring.addFromMnemonic(mnemonic);
    }
}

export const accountFactory = new AccountFactory();