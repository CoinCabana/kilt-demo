import {kiltConnector} from "./kilt-connector";
import {workshopDemo} from "./demo/workshop-demo";

async function main() {

  await kiltConnector.initialize();

  // Setup
  const { attester, claimer, verifier } = await workshopDemo.setup();

  // Claimer gets ctype from Attester
  const ctypeJSON = await attester.getCtype();

  // Claimer forms a claim for the ctype
  const content = { name: 'Alice', age: 25 };
  const claimJSON = await claimer.createClaim(ctypeJSON, content);

  // Claimer creates an attestation request
  const requestJSON = await claimer.createRequest(claimJSON);

  // Claimer sends request to the Attester for approval or rejection
  const credentialJSON = await attester.attestCredential(requestJSON);
  if (!credentialJSON) throw Error('credential denied');

  // console.log('credentialJSON');
  // console.log(credentialJSON);

  // Claimer gets a challenge from Verifier
  const challenge = verifier.getChallenge();

  // Claimer creates a signed presentation using credential and challenge
  const presentationJSON = await claimer.createPresentation(credentialJSON, challenge);

  // console.log('presentationJSON');
  // console.log(presentationJSON);

  // Claimer sends their presentation Verifier for processing
  const isVerified = await verifier.verifyCredential(presentationJSON, challenge);

  // presentation is verified or denied by the Verifier
  if (isVerified) console.log('woohoo verified, workshop complete!');
  else console.log('booo verification denied!');

  await kiltConnector.disconnect();
  console.log('disconnected...');
}

main();