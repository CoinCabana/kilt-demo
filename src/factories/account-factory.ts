import {Keyring} from "@kiltprotocol/utils";

class AccountFactory {

    createAccount(mnemonic: string) {
        const keyring = new Keyring({ ss58Format: 38, type: 'sr25519'});
        return keyring.addFromMnemonic(mnemonic);
    }

    createAccount2(mnemonic: string) {
        // const keyring = new Keyring({ ss58Format: 38, type: 'sr25519'});
        const test1 = new Keyring({  type: 'ethereum'});
        const test2 = new Keyring({  type: 'ecdsa'});
        const kr1 = test1.addFromUri(mnemonic)
        const kr2 = test2.addFromUri(mnemonic)
        console.log(kr1.address, Buffer.from(kr1.publicKey).toString('hex'))
        console.log(kr2.address, Buffer.from(kr2.publicKey).toString('hex'))
        return kr1;
    }
}

export const accountFactory = new AccountFactory();