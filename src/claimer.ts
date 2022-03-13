import {KeyringPair, KeystoreSigner} from "@kiltprotocol/types";
import {Claim, Credential, Did, IClaim, ICredential, RequestForAttestation} from "@kiltprotocol/sdk-js";
import {keypairUtil, SignEncryptKeyPairs} from "./utils/keypair-util";
import {didService} from "./services/did-service";
import {accountFactory} from "./factories/account-factory";
import {CidKeystore} from "./demo/cid-keystore";

export class Claimer {
    private account: KeyringPair;
    private keystore: CidKeystore;
    private didDetails: Did.LightDidDetails;
    private didUri: string;
    private keyPairs: SignEncryptKeyPairs;

    constructor(private mnemonic: string) {}

    async initialize () {
        this.account = accountFactory.createAccount(this.mnemonic);
        this.keystore = new CidKeystore();

        // Create and store the key pairs in the keystore
        this.keyPairs = await keypairUtil.generateLightKeyPairs(this.keystore, this.mnemonic);

        this.didDetails = await didService.createLightDid(this.keyPairs);

        this.didUri = this.didDetails.did;
    }

    async createClaim(ctypeJSON, content) {
        const ctype = JSON.parse(ctypeJSON);
        const claim = this.createClaim2(this.didDetails, ctype, content);
        return JSON.stringify(claim);
    }

    // creates claim request from claim returning data
    async createRequest(claimJSON: string) {
        // parse claim, load account, build request return data
        const claim: IClaim = JSON.parse(claimJSON);
        try {
            // use test request if it exists
            const oldRequest = require('./_request.json');
            return JSON.stringify(oldRequest);
        } catch(e) {
            // otherwise create a new one
            const newRequest = await this.createRequest2(this.didDetails, this.keystore, claim);
            return JSON.stringify(newRequest);
        }
    }

    async createPresentation(credentialJSON: string, challenge: string) {
        const credential: ICredential = JSON.parse(credentialJSON);
        const presentation = await this.createPresentation2(credential, challenge, this.didDetails, this.keystore);
        return JSON.stringify(presentation);
    }

    private createClaim2(lightDid, ctype, content) {
        const claim = Claim.fromCTypeAndClaimContents(
            ctype,
            content,
            lightDid.did
        );

        return claim;
    }

    private async createPresentation2(credentialObj: ICredential, challenge: string, lightDid: Did.LightDidDetails, keystore: CidKeystore) {
        // creates a Credential from object
        const credential = new Credential(credentialObj)

        // creates the presentation from credential, keystore, did and challenge
        const presentation = await credential.createPresentation({
            signer: keystore,
            claimerDid: lightDid,
            challenge: challenge,
        });

        return presentation;
    }

    private async createRequest2(lightDid: Did.LightDidDetails, keystore: CidKeystore, claim: IClaim) {
        const request = RequestForAttestation.fromClaim(claim);
        await request.signWithDidKey(keystore, lightDid, lightDid.authenticationKey.id);

        console.log('\n\nsave this to ./claimer/_request.json for testing\n\n');
        console.log(JSON.stringify(request, null, 2))
        console.log('\n\n');

        return request;
    }





}