import * as fs from 'fs';
import * as path from 'path';
import { Token } from 'goplus/token';
import { RugPull } from 'goplus/rug_pull';

interface TokenResult {
  token_security: {
    [key: string]: any;
  };
  rug_pull_security: {
    [key: string]: any;
  };
}

async function analyzeToken(address: string, chainId: string): Promise<TokenResult | null> {
  try {
    // Analyze token security
    const tokenData = await new Token().tokenSecurity(chainId, [address]);

    // Analyze rug pull risk
    const rugPullData = await new RugPull().rugPullSecurity(chainId, address);

    // Combine the results into a single object
    const result: TokenResult = {
      token_security: tokenData.toObject(),
      rug_pull_security: rugPullData.toObject(),
    };

    return result;
  } catch (e) {
    console.error(`Error occurred during analysis: ${e.message}`);
    return null;
  }
}

function generateReport(result: TokenResult): string {
  let report = '';

  // Token Security Analysis Breakdown
  const tokenData = Object.values(result.token_security.result)[0];
  if (tokenData) {
    report += `- Open Source: ${tokenData.is_open_source === '1' ? 'Yes' : tokenData.is_open_source === '0' ? 'No' : 'Unknown'}\n`;
    report += `- Proxy Contract: ${tokenData.is_proxy === '1' ? 'Yes' : tokenData.is_proxy === '0' ? 'No' : 'Unknown'}\n`;
    report += `- Mint Function: ${tokenData.is_mintable === '1' ? 'Yes' : tokenData.is_mintable === '0' ? 'No' : 'Unknown'}\n`;
    report += `- Owner Address: ${tokenData.owner_address || 'Unknown'}\n`;
    report += `- Can Take Back Ownership: ${tokenData.can_take_back_ownership === '1' ? 'Yes' : tokenData.can_take_back_ownership === '0' ? 'No' : 'Unknown'}\n`;
    report += `- Owner Can Change Balance: ${tokenData.owner_change_balance === '1' ? 'Yes' : tokenData.owner_change_balance === '0' ? 'No' : 'Unknown'}\n`;
    report += `- Hidden Owner: ${tokenData.hidden_owner === '1' ? 'Yes' : tokenData.hidden_owner === '0' ? 'No' : 'Unknown'}\n`;
    report += `- Selfdestruct: ${tokenData.selfdestruct === '1' ? 'Yes' : tokenData.selfdestruct === '0' ? 'No' : 'Unknown'}\n`;
    report += `- External Call: ${tokenData.external_call === '1' ? 'Yes' : tokenData.external_call === '0' ? 'No' : 'Unknown'}\n`;
    report += `- In DEX: ${tokenData.is_in_dex === '1' ? 'Yes' : tokenData.is_in_dex === '0' ? 'No' : 'Unknown'}\n`;
    report += `- Buy Tax: ${tokenData.buy_tax || 'Unknown'}\n`;
    report += `- Sell Tax: ${tokenData.sell_tax || 'Unknown'}\n`;
    report += `- Can't Buy: ${tokenData.cannot_buy === '1' ? 'Yes' : tokenData.cannot_buy === '0' ? 'No' : 'Unknown'}\n`;
    report += `- Can't Sell All: ${tokenData.cannot_sell_all === '1' ? 'Yes' : tokenData.cannot_sell_all === '0' ? 'No' : 'Unknown'}\n`;
    report += `- Slippage Modifiable: ${tokenData.slippage_modifiable === '1' ? 'Yes' : tokenData.slippage_modifiable === '0' ? 'No' : 'Unknown'}\n`;
    report += `- Honeypot: ${tokenData.is_honeypot === '1' ? 'Yes' : tokenData.is_honeypot === '0' ? 'No' : 'Unknown'}\n`;
    report += `- Transfer Pausable: ${tokenData.transfer_pausable === '1' ? 'Yes' : tokenData.transfer_pausable === '0' ? 'No' : 'Unknown'}\n`;
    report += `- Blacklist: ${tokenData.is_blacklisted === '1' ? 'Yes' : tokenData.is_blacklisted === '0' ? 'No' : 'Unknown'}\n`;
    report += `- Whitelist: ${tokenData.is_whitelisted === '1' ? 'Yes' : tokenData.is_whitelisted === '0' ? 'No' : 'Unknown'}\n`;
    report += `- Anti Whale: ${tokenData.is_anti_whale === '1' ? 'Yes' : tokenData.is_anti_whale === '0' ? 'No' : 'Unknown'}\n`;
    report += `- Anti Whale Modifiable: ${tokenData.anti_whale_modifiable === '1' ? 'Yes' : tokenData.anti_whale_modifiable === '0' ? 'No' : 'Unknown'}\n`;
    report += `- Trading Cooldown: ${tokenData.trading_cooldown === '1' ? 'Yes' : tokenData.trading_cooldown === '0' ? 'No' : 'Unknown'}\n`;
    report += `- Personal Slippage Modifiable: ${tokenData.personal_slippage_modifiable === '1' ? 'Yes' : tokenData.personal_slippage_modifiable === '0' ? 'No' : 'Unknown'}\n`;
    report += `- Token Name: ${tokenData.token_name || 'Unknown'}\n`;
    report += `- Token Symbol: ${tokenData.token_symbol || 'Unknown'}\n`;
    report += `- Holder Count: ${tokenData.holder_count || 'Unknown'}\n`;
    report += `- Total Supply: ${tokenData.total_supply || 'Unknown'}\n`;
    report += `- Creator Address: ${tokenData.creator_address || 'Unknown'}\n`;
    report += `- Creator Balance: ${tokenData.creator_balance || 'Unknown'}\n`;
    report += `- Creator Percent: ${tokenData.creator_percent || 'Unknown'}\n`;
    report += `- LP Holder Count: ${tokenData.lp_holder_count || 'Unknown'}\n`;
    report += `- LP Total Supply: ${tokenData.lp_total_supply || 'Unknown'}\n`;
    report += `- Is True Token: ${tokenData.is_true_token === '1' ? 'Yes' : tokenData.is_true_token === '0' ? 'No' : 'Unknown'}\n`;
    report += `- Is Airdrop Scam: ${tokenData.is_airdrop_scam === '1' ? 'Yes' : tokenData.is_airdrop_scam === '0' ? 'No' : 'Unknown'}\n`;
    report += `- Is In Trust List: ${tokenData.trust_list === '1' ? 'Yes' : 'Unknown'}\n`;

    const fakeToken = tokenData.fake_token;
    if (fakeToken) {
      report += `- Fake Token: ${fakeToken.value === 1 ? 'Yes' : 'No'}\n`;
      report += `  - True Token Address: ${fakeToken.true_token_address}\n`;
    } else {
      report += `- Fake Token: Unknown\n`;
    }
  }

  // Rug Pull Security Analysis Breakdown
  const rugPullData = result.rug_pull_security.result;
  if (rugPullData) {
    const owner = rugPullData.owner;
    if (owner) {
      report += `- Owner Name: ${owner.owner_name || 'Unknown'}\n`;
      report += `- Owner Address: ${owner.owner_address || 'Unknown'}\n`;
      report += `- Owner Type: ${owner.owner_type || 'Unknown'}\n`;
    } else {
      report += `- Owner: No owner information available.\n`;
    }

    report += `- Privilege Withdraw: ${rugPullData.privilege_withdraw === 1 ? 'Yes' : rugPullData.privilege_withdraw === 0 ? 'No' : 'Unknown'}\n`;
    report += `- Cannot Withdraw: ${rugPullData.withdraw_missing === 1 ? 'Yes' : rugPullData.withdraw_missing === 0 ? 'No' : 'Unknown'}\n`;
    report += `- Contract Verified: ${rugPullData.is_open_source === 1 ? 'Yes' : 'No'}\n`;
    report += `- Blacklist Function: ${rugPullData.blacklist === 1 ? 'Yes' : rugPullData.blacklist === 0 ? 'No' : 'Unknown'}\n`;
    report += `- Contract Name: ${rugPullData.contract_name || 'Unknown'}\n`;
    report += `- Self-Destruct: ${rugPullData.selfdestruct === 1 ? 'Yes' : rugPullData.selfdestruct === 0 ? 'No' : 'Unknown'}\n`;
    report += `- Potential Approval Abuse: ${rugPullData.approval_abuse === 1 ? 'Yes' : rugPullData.approval_abuse === 0 ? 'No' : 'Unknown'}\n`;
    report += `- Proxy Contract: ${rugPullData.is_proxy === 1 ? 'Yes' : rugPullData.is_proxy === 0 ? 'No' : 'Unknown'}\n`;
  } else {
    report += `No rug pull security data available.\n`;
  }

  return report;
}

function generateReportForNetwork(result: TokenResult, network: string): string {
  let report = `## ${network.charAt(0).toUpperCase() + network.slice(1)}\n\n`;
  report += generateReport(result);
  return report;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length < 1) {
    console.log('Please provide the relative path to the data.json file as a command-line argument.');
    return;
  }

  const dataFile = path.join(path.dirname(path.dirname(__dirname)), args[0]);
  if (!fs.existsSync(dataFile)) {
    console.error(`File not found: ${dataFile}`);
    return;
  }

  const data = JSON.parse(fs.readFileSync(dataFile, 'utf-8'));

  const tokenNetworks: { [key: string]: string } = {
    base: '8453',
    'base-sepolia': '84532',
    ethereum: '1',
    lyra: '957',
    metal: '1750',
    'metal-sepolia': '1740',
    mode: '34443',
    'mode-sepolia': '919',
    optimism: '10',
    'optimism-sepolia': '11155420',
    orderly: '291',
    pgn: '424',
    'pgn-sepolia': '58008',
    sepolia: '11155111',
    superlumio: '8866',
    zora: '7777777',
    'zora-sepolia': '999999999',
  };

  let report = '# Token Analysis Results\n\n';
  for (const network in tokenNetworks) {
    if (data.tokens[network]) {
      const address = data.tokens[network].address;
      const result = await analyzeToken(address, tokenNetworks[network]);
      if (result) {
        report += generateReportForNetwork(result, network);
        report += '\n';
      } else {
        console.error(`Failed to analyze the token on ${network}.`);
      }
    }
  }

  if (report.trim() === '# Token Analysis Results') {
    console.log('No supported token networks found in the data.json file.');
  } else {
    report += '\nReport definitions:\n';
    report += '* https://docs.gopluslabs.io/reference/response-details\n';
    report += '* https://docs.gopluslabs.io/reference/response-details-7\n';
    console.log(report.trim());
  }
}

main();