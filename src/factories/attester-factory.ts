import {Did} from "@kiltprotocol/sdk-js";
import {Keyring} from "@kiltprotocol/utils";
import {keypairUtil} from "../utils/keypair-util";
import {didService} from "../services/did-service";
import {CidKeystore} from "../demo/cid-keystore";

class AttesterFactory {

    async create (keystore: CidKeystore, mnemonic: string) {
        const keyring = new Keyring({ ss58Format: 38, type: 'sr25519'});

        const account = keyring.addFromMnemonic(mnemonic);

        const hasDid = await didService.hasDid(account.address);

        if (hasDid) {
            throw Error(`The Identity already exists on chain: ${account.address}\n`)
        }

        // generate the keypairs and load the DID if we have it
        const keyPairs = await keypairUtil.generateKeyPairs(keystore, mnemonic);

        return await didService.createFullDid(keystore, keyPairs, account);
    }


}

export const attesterFactory = new AttesterFactory();