import * as Kilt from '@kiltprotocol/sdk-js';
import {Claimer} from "../claimer";
import {DemoAttester} from "./demo-attester";

const ATTESTER_MNEMONIC = "fork powder vendor depart license question snap bid seed witness library juice"
const CLAIMER_MNEMONIC = "quick catch expect matter sound clump employ topic inquiry error practice fitness";

class WorkshopDemo {

    async setup() {
        const attester = new DemoAttester(ATTESTER_MNEMONIC);
        const claimer = new Claimer(CLAIMER_MNEMONIC);
        const verifier = new Verifier();

        await attester.initialize();
        await claimer.initialize();

        return { attester, claimer, verifier };
    }
    //"did:cabana:3840972389461827481264892731"
    //verify.xyz/discord/36786222 -> DID
    //   /verify @DocHolliday -> bot.service -> DID.resolve(cabana.DID) -> Adam Jones, CEO; EnzedFresh, Discord Moderator
}

export const workshopDemo = new WorkshopDemo();

class Verifier {

    getChallenge() {
        return Kilt.Utils.UUID.generate();
    }

    // verifies validity, ownership & attestation returning true|false
    async verifyCredential(presentationJSON, challenge) {
        const presentation = JSON.parse(presentationJSON);
        const credential = new Kilt.Credential(presentation);

        const isValid = await credential.verify();

        const isSenderOwner = await Kilt.Credential.verify(presentation, { challenge });

        const isAttested = !credential.attestation.revoked;

        return isValid && isSenderOwner && isAttested
    }
}