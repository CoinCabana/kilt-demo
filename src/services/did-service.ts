import {VerificationKeyType} from "@kiltprotocol/sdk-js";
import {SignEncryptKeyPairs} from "../utils/keypair-util";
import {KeyringPair, EncryptionKeyType} from "@kiltprotocol/types";
import {CidKeystore} from "../demo/cid-keystore";
import * as Kilt from "@kiltprotocol/sdk-js";
import {kiltConnector} from "../kilt-connector";
import {LightDidSupportedVerificationKeyType} from "@kiltprotocol/did";

const lightKeypairTypeForAlg: Record<string, LightDidSupportedVerificationKeyType> = {
    ed25519: VerificationKeyType.Ed25519,
    sr25519: VerificationKeyType.Sr25519
}

const keypairTypeForAlg: Record<string, VerificationKeyType> = {
    ed25519: VerificationKeyType.Ed25519,
    sr25519: VerificationKeyType.Sr25519,
    ecdsa: VerificationKeyType.Ecdsa,
    'ecdsa-secp256k1': VerificationKeyType.Ecdsa
}

const encryptionKeyTypeForAlg: Record<string, EncryptionKeyType> = {
    "x25519-xsalsa20-poly1305": EncryptionKeyType.X25519
}

const getLightVerificationKeyTypeForAlg = (alg: string):  LightDidSupportedVerificationKeyType => lightKeypairTypeForAlg[alg];
const getVerificationKeyTypeForAlg = (alg: string): VerificationKeyType => keypairTypeForAlg[alg];
const getEncryptionKeyTypeForAlg = (alg: string): EncryptionKeyType => encryptionKeyTypeForAlg[alg];

class DidService {

    async hasDid (address: string) {

        // check to see if the did is already on chain
        const found = await this.getDid(address);

        return !!found;
    }

    async getDid (address: string) {
        return Kilt.Did.FullDidDetails.fromChainInfo(address)
    }

    async createLightDid(keyPairs: SignEncryptKeyPairs) {

        // build the Claimer keys object
        const keys = {
            authenticationKey: {
                publicKey: keyPairs.signing.publicKey,
                type: getLightVerificationKeyTypeForAlg(keyPairs.signing.alg)
            },
            encryptionKey: {
                publicKey: keyPairs.encryption.publicKey,
                type: getEncryptionKeyTypeForAlg(keyPairs.encryption.alg)
            }
        };

        // create the DID
        return Kilt.Did.LightDidDetails.fromDetails(keys);
    }

    async createFullDid(keystore: CidKeystore, keyPairs: SignEncryptKeyPairs, account: KeyringPair) {
        // build the Attester keys object
        const keys = {
            authentication: {
                publicKey: keyPairs.signing.publicKey,
                type: getVerificationKeyTypeForAlg(keyPairs.signing.alg)
            },
            keyAgreement: {
                publicKey: keyPairs.encryption.publicKey,
                type: getEncryptionKeyTypeForAlg(keyPairs.encryption.alg)
            },
            capabilityDelegation: {
                publicKey: keyPairs.signing.publicKey,
                type: getVerificationKeyTypeForAlg(keyPairs.signing.alg)
            },
            assertionMethod: {
                publicKey: keyPairs.signing.publicKey,
                type: getVerificationKeyTypeForAlg(keyPairs.signing.alg)
            },
        };

        // // get extrinsic and didUri
        // const { extrinsic, did: didUri } = await Did.DidUtils.writeDidFromPublicKeys(
        //     keystore as any,
        //     account.address,
        //     keys
        // );
        //
        // // write the DID to blockchain
        // await BlockchainUtils.signAndSubmitTx(extrinsic, account, {
        //     reSign: true,
        //     resolveOn: BlockchainUtils.IS_FINALIZED,
        // });

        const api = await kiltConnector.api();

        const builder = new Kilt.Did.FullDidCreationBuilder(api, keys.authentication);

        const fullDid = await builder
            .addEncryptionKey(keys.keyAgreement)
            .setAttestationKey(keys.assertionMethod)
            .setDelegationKey(keys.capabilityDelegation)
            .consumeWithHandler(keystore, account.address, async (creationTx) => {
                await Kilt.BlockchainUtils.signAndSubmitTx(creationTx, account, {
                    reSign: true,
                    resolveOn: Kilt.BlockchainUtils.IS_FINALIZED
                })
            })

        return fullDid;
    }
}

export const didService = new DidService();
