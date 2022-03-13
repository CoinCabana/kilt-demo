import {cryptoWaitReady} from "@polkadot/util-crypto";
import * as Kilt from '@kiltprotocol/sdk-js';
import {appEnv} from "./app-env";
import {accountFactory} from "./factories/account-factory";

const SEED_SECRET = 'receive clutch item involve chaos clutch furnace arrest claw isolate okay together';

class KiltConnector {

    async initialize () {
        // wait for the crypto library to be ready
        await cryptoWaitReady();

        // connect to the KILT wss node
        await Kilt.init({ address: appEnv.WSS_ADDRESS });
    }

    async api() {
        const { api } = await Kilt.connect();
        return api;
    }

    async bootstrapAttester (mnemonic: string) {
        //MashNet Seed Account
        const seedKeyring = new Kilt.Utils.Keyring({ ss58Format: 38, type: 'ed25519'});
        const seedAccount = seedKeyring.addFromMnemonic(SEED_SECRET);

        const attesterAccount = accountFactory.createAccount(mnemonic);

        const balances = await Kilt.Balance.getBalances(attesterAccount.address);

        console.log('ATTESTER BALANCE - ', attesterAccount.address);
        console.log(JSON.stringify(balances,null,2));

        if (balances.free.isZero()) {
            console.log('transferring...', attesterAccount.address);
            await this.transfer(seedAccount, attesterAccount.address, 500);
        }
    }

    async disconnect() {
        await Kilt.disconnect();
    }

    private async transfer(fromAccount, address, transferAmount) {
        await Kilt.Balance.getTransferTx(address, transferAmount, 0).then((tx) =>
            Kilt.BlockchainUtils.signAndSubmitTx(tx, fromAccount, {
                resolveOn: Kilt.BlockchainUtils.IS_FINALIZED,
                reSign: true,
            })
        );

        const balances = await Kilt.Balance.getBalances(address);

        console.log('BALANCES (after transfer)');
        console.log(JSON.stringify(balances,null,2));
    }
}

export const kiltConnector = new KiltConnector();