import {BlockchainUtils, Did} from "@kiltprotocol/sdk-js";
import {SignEncryptKeyPairs} from "../utils/keypair-util";
import {KeyringPair} from "@kiltprotocol/types";
import {CidKeystore} from "../demo/cid-keystore";

class DidService {

    async hasDid (address: string) {

        // check to see if the did is already on chain
        const found = await this.getDid(address);

        return !!found;
    }

    async getDid (address: string) {
        return Did.DidChain.queryById(address);
    }

    async createLightDid(keyPairs: SignEncryptKeyPairs) {

        // build the Claimer keys object
        const keys = {
            authenticationKey: {
                publicKey: keyPairs.signing.publicKey,
                type: CidKeystore.getKeypairTypeForAlg(
                    keyPairs.signing.alg
                ),
            },
            encryptionKey: {
                publicKey: keyPairs.encryption.publicKey,
                type: CidKeystore.getKeypairTypeForAlg(
                    keyPairs.encryption.alg
                ),
            },
        };

        // create the DID
        const lightDid = new Did.LightDidDetails(keys);

        // prompt to store it for reference
        // if (!didUri) {
        //     console.log('\nsave following to .env to continue\n');
        //     console.error(`CLAIMER_DID_URI=${lightDid.did}\n`);
        //     process.exit();
        // }

        return lightDid
    }

    async createFullDid(keystore: CidKeystore, keyPairs: SignEncryptKeyPairs, account: KeyringPair) {
        // build the Attester keys object
        const keys = {
            authentication: {
                publicKey: keyPairs.signing.publicKey,
                type: CidKeystore.getKeypairTypeForAlg(
                    keyPairs.signing.alg
                ),
            },
            keyAgreement: {
                publicKey: keyPairs.encryption.publicKey,
                type: CidKeystore.getKeypairTypeForAlg(
                    keyPairs.encryption.alg
                ),
            },
            capabilityDelegation: {
                publicKey: keyPairs.signing.publicKey,
                type: CidKeystore.getKeypairTypeForAlg(
                    keyPairs.signing.alg
                ),
            },
            assertionMethod: {
                publicKey: keyPairs.signing.publicKey,
                type: CidKeystore.getKeypairTypeForAlg(
                    keyPairs.signing.alg
                ),
            },
        };

        // get extrinsic and didUri
        const { extrinsic, did: didUri } = await Did.DidUtils.writeDidFromPublicKeys(
            keystore as any,
            account.address,
            keys
        );

        // write the DID to blockchain
        await BlockchainUtils.signAndSubmitTx(extrinsic, account, {
            reSign: true,
            resolveOn: BlockchainUtils.IS_FINALIZED,
        });

        return didUri;
    }
}

export const didService = new DidService();
