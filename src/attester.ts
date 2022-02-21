import * as Kilt from '@kiltprotocol/sdk-js';
import {KeyringPair} from "@kiltprotocol/types";
import {BlockchainUtils, CType, Did, IDidResolvedDetails} from "@kiltprotocol/sdk-js";
import {didService} from "./services/did-service";
import {keypairUtil, SignEncryptKeyPairs} from "./utils/keypair-util";
import {accountFactory} from "./factories/account-factory";
import {CidKeystore} from "./demo/cid-keystore";

const { mnemonicGenerate, base58Encode } = require('@polkadot/util-crypto');

const signingMnemonic = 'program chunk true glue peace woman citizen goat library wagon swamp firm';

export abstract class Attester {

    protected account: KeyringPair;
    protected keystore: CidKeystore;
    protected didUri: string;
    protected keyPairs: SignEncryptKeyPairs;
    protected fullDid: IDidResolvedDetails;

    protected constructor(protected mnemonic: string) {}

    async initialize () {
        this.account = accountFactory.createAccount(this.mnemonic);
        this.keystore = new CidKeystore();

        // const newSecret = signingMnemonic;//mnemonicGenerate();
        //
        // console.log('cycle keys: '+newSecret);

        // Create and store the key pairs in the keystore
        this.keyPairs = await keypairUtil.generateKeyPairs(this.keystore, this.mnemonic);

        console.log('keyPairs.signing.publicKey - ', base58Encode(this.keyPairs.signing.publicKey));

        this.fullDid = await this.getOrCreateFullDid();

        console.log(JSON.stringify(Did.exportToDidDocument(this.fullDid.details, 'application/json'), null, 2))
    }

    abstract createCtype(): CType;

    async getCtype() {
        const ctype = await this.getCtype2();
        return JSON.stringify(ctype);
    }

    async attestCredential(requestJSON) {
        // parse, load account, attest credential, return as data
        const request = JSON.parse(requestJSON);
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
        const tx = await ctype.store();
        const extrinsic = await this.fullDid.details['authorizeExtrinsic'](tx, this.keystore as any, this.account.address);

        console.log('Attester.anchoring new CTYPE - ', ctype.schema.title);

        // write to chain then return ctype
        await BlockchainUtils.signAndSubmitTx(extrinsic, this.account, {
            resolveOn: BlockchainUtils.IS_FINALIZED,
            reSign: true,
        });

        console.log('Attester.anchoring new CTYPE - COMPLETED');

        return ctype;
    }

    async attestCredential2(account, fullDid, keystore, request) {
        // build the attestation object
        const attestation = Kilt.Attestation.fromRequestAndDid(request, fullDid.details.did);

        // check the request content and deny based on your business logic..
        // if (request.claim.content.age < 20) return null;

        // if the attestation is not yet on chain store it
        if (!await Kilt.Attestation.query(attestation.claimHash)) {

            // form tx and authorized extrinsic
            const tx = await attestation.store();
            const extrinsic = await fullDid.details.authorizeExtrinsic(
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

        const fullDid = await didService.getDid(this.account.address);

        // if we don't have the didUri create the on chain DID
        if (fullDid && !forceCreate) {
            this.didUri = fullDid.did;
        }
        else {

            console.log('Attester creating FullDid');

            await didService.createFullDid(this.keystore, this.keyPairs, this.account);

            // make sure the did is on chain
            const onChain = await Did.DidChain.queryById(this.account.address)
            if (!onChain) throw Error(`failed to find on chain: ${this.account.address}\n`)

            this.didUri = onChain.did;
        }

        console.log('Attester.FullDid found', this.didUri);

        // load and return the DID using the default resolver
        return await Did.resolveDoc(this.didUri);
    }

}