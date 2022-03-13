import {Did} from "@kiltprotocol/sdk-js";
import {CidKeystore} from "../demo/cid-keystore";

export type SignEncryptKeyPairs = {
    signing: {
        publicKey: Uint8Array,
        alg: string
    },
    encryption: {
        publicKey: Uint8Array,
        alg: string
    },
}

class KeypairUtil {

    async generateKeyPairs(keystore: CidKeystore, mnemonic: string): Promise<SignEncryptKeyPairs> {
        // signing keypair
        const signing = await keystore.generateKeypair({
            alg: Did.SigningAlgorithms.EcdsaSecp256k1,
            seed: mnemonic,
        });

        // encryption keypair
        const encryption = await keystore.generateKeypair({
            alg: Did.EncryptionAlgorithms.NaclBox,
            seed: mnemonic,
        });

        return { signing, encryption }
    }

    async generateLightKeyPairs(keystore: CidKeystore, mnemonic: string): Promise<SignEncryptKeyPairs> {
        // signing keypair
        const signing = await keystore.generateKeypair({
            alg: Did.SigningAlgorithms.Sr25519,
            seed: mnemonic,
        });

        // encryption keypair
        const encryption = await keystore.generateKeypair({
            alg: Did.EncryptionAlgorithms.NaclBox,
            seed: mnemonic,
        });

        return { signing, encryption }
    }
}

export const keypairUtil = new KeypairUtil();