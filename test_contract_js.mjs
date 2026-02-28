import { createClient, createAccount } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';
import { TransactionStatus } from 'genlayer-js/types';

const RPC_URL = process.env.GENLAYER_RPC_URL || 'https://studio.genlayer.com/api';
const CONTRACT_ADDRESS =
  process.env.GENLAYER_CONTRACT || '0x57a3212cbca238455291ad8ca2CA51F4D269Ae6F';
const PRIVATE_KEY = process.env.GENLAYER_PRIVATE_KEY || '';

if (!PRIVATE_KEY) {
  console.error('Missing GENLAYER_PRIVATE_KEY env var.');
  process.exit(1);
}

async function main() {
  const account = createAccount(PRIVATE_KEY);
  const client = createClient({
    chain: studionet,
    endpoint: RPC_URL,
    account,
  });

  await client.initializeConsensusSmartContract();

  const txData =
    process.argv[2] || 'transfer(user=0xabc, amount=1)';
  const txHash =
    process.argv[3] || '0xTEST123';

  const writeHash = await client.writeContract({
    address: CONTRACT_ADDRESS,
    functionName: 'analyze_transaction',
    args: [txData, txHash],
    value: 0n,
  });

  const receipt = await client.waitForTransactionReceipt({
    hash: writeHash,
    status: TransactionStatus.ACCEPTED,
    retries: 50,
    interval: 5000,
  });

  console.log('Write receipt:', receipt);

  const analysis = await client.readContract({
    address: CONTRACT_ADDRESS,
    functionName: 'get_tx_analysis_readable',
    args: [txHash],
  });

  console.log('Analysis:', analysis);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
