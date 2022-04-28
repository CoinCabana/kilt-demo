import * as Kilt from '@kiltprotocol/sdk-js';
import {KeyringPair} from "@kiltprotocol/types";
import {BlockchainUtils, CType, Did, IDidDetails, IRequestForAttestation} from "@kiltprotocol/sdk-js";
import {didService} from "./services/did-service";
import {keypairUtil, SignEncryptKeyPairs} from "./utils/keypair-util";
import {accountFactory} from "./factories/account-factory";
import {CidKeystore} from "./demo/cid-keystore";

const { mnemonicGenerate, base58Encode } = require('@polkadot/util-crypto');

const signingMnemonic = 'program chunk true glue peace woman citizen goat library wagon swamp firm';

export abstract class Attester {

    protected account: KeyringPair;
    protected keystore: CidKeystore;
    // protected didUri: string;
    protected keyPairs: SignEncryptKeyPairs;
    protected fullDid: Did.FullDidDetails;

    protected constructor(protected mnemonic: string) {}

    async initialize () {
        this.account = accountFactory.createAccount(this.mnemonic);
        this.keystore = new CidKeystore();

        // const newSecret = signingMnemonic;//mnemonicGenerate();
        //
        // console.log('cycle keys: '+newSecret);

        // throw new Error('done');

        // Create and store the key pairs in the keystore
        this.keyPairs = await keypairUtil.generateKeyPairs(this.keystore, this.mnemonic);

        // console.log('keyPairs.signing.publicKey - ', base58Encode(this.keyPairs.signing.publicKey));

        this.fullDid = await this.getOrCreateFullDid();

        //console.log(JSON.stringify(Did.exportToDidDocument(this.fullDid, 'application/json'), null, 2))
    }

    abstract createCtype(): CType;

    async getCtype() {
        const ctype = await this.getCtype2();
        return JSON.stringify(ctype);
    }

    async attestCredential(requestJSON: string) {
        // parse, load account, attest credential, return as data
        const request: IRequestForAttestation = JSON.parse(requestJSON);
        const credential = await this.attestCredential2(this.account, this.fullDid, this.keystore, request);
        return JSON.stringify(credential);
    }

    //register CTYPE on first create.
    private async getCtype2() {
        // get the CTYPE and see if it's stored, if yes return it
        const ctype = this.createCtype();
        const isStored = await ctype.verifyStored();
        if (isStored) return ctype;

        // authorize the extrinsic
        const tx = await ctype.getStoreTx();
        const extrinsic = await this.fullDid.authorizeExtrinsic(tx, this.keystore, this.account.address);

        console.log('Attester.anchoring new CTYPE - ', ctype.schema.title);

        // write to chain then return ctype
        await BlockchainUtils.signAndSubmitTx(extrinsic, this.account, {
            resolveOn: BlockchainUtils.IS_FINALIZED,
            reSign: true,
        });

        console.log('Attester.anchoring new CTYPE - COMPLETED');

        return ctype;
    }

    async attestCredential2(account: KeyringPair, fullDid: Did.FullDidDetails, keystore: CidKeystore, request: IRequestForAttestation) {
        // build the attestation object
        const attestation = Kilt.Attestation.fromRequestAndDid(request, fullDid.did);

        // check the request content and deny based on your business logic..
        // if (request.claim.content.age < 20) return null;

        // if the attestation is not yet on chain store it
        if (!await Kilt.Attestation.query(attestation.claimHash)) {

            // form tx and authorized extrinsic
            const tx = await attestation.getStoreTx();
            const extrinsic = await fullDid.authorizeExtrinsic(
                tx,
                keystore,
                account.address
            );

            console.log('Attester - write new attestation - ', attestation.claimHash);

            // write to chain
            await Kilt.BlockchainUtils.signAndSubmitTx(extrinsic, account, {
                resolveOn: Kilt.BlockchainUtils.IS_FINALIZED,
            });

            console.log('Attester - write new attestation - COMPLETED');
        }

        // build the credential and return it
        const credential = Kilt.Credential.fromRequestAndAttestation(
            request,
            attestation
        );

        return credential;
    }

    private async getOrCreateFullDid(forceCreate = false) {

        console.log('getOrCreateFullDid for', this.account.address);

        let fullDid = !forceCreate && await didService.getDid(this.account.address);

        // if we don't have the didUri create the on chain DID
        if (!fullDid) {

            console.log('Attester creating FullDid');

            fullDid = await didService.createFullDid(this.keystore, this.keyPairs, this.account);

            console.log('Attester FullDid - ', fullDid.did);

            const json = Did.exportToDidDocument(fullDid, 'application/json')

            console.log(JSON.stringify(json, null, 2));

            // make sure the did is already on chain
            // fullDid = await didService.getDid(this.account.address)
            if (!fullDid)
                throw Error(`failed to find on chain did: did:kilt:${this.account.address}`)
        }

        console.log('Attester.FullDid found', fullDid.did);

        // load and return the DID using the default resolver
        return fullDid;
    }

}