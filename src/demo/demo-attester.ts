import {Attester} from "../attester";
import {CType, Did} from "@kiltprotocol/sdk-js";
import {kiltConnector} from "../kilt-connector";

export class DemoAttester extends Attester {

    constructor(mnemonic: string) {
        super(mnemonic);
    }

    async initialize () {
        await kiltConnector.bootstrapAttester(this.mnemonic)

        await super.initialize();
    }

    createCtype() {
        return CType.fromSchema({
            $schema: 'http://kilt-protocol.org/draft-01/ctype#',
            title: 'Drivers License',
            properties: {
                name: {
                    type: 'string',
                },
                age: {
                    type: 'integer',
                },
            },
            type: 'object',
        });
    }
}