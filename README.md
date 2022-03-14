

### Install dependencies
yarn install

### Build
npm run build


### Run docker for local kilt-node
docker run -d --name kilt-node -p 9944:9944 kiltprotocol/mashnet-node:develop --dev --ws-port 9944 --ws-external --rpc-external --tmp

### Run demo
node dist/demo.js

### View local Node events
https://polkadot.js.org/apps/?rpc=ws%3A%2F%2F127.0.0.1%3A9944#/explorer
