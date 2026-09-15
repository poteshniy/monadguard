const solc=require('solc'),fs=require('fs'),path=require('path');
const src=fs.readFileSync('contracts/ScanRegistry.sol','utf8');
const input={language:'Solidity',sources:{'ScanRegistry.sol':{content:src}},
settings:{optimizer:{enabled:true,runs:200},evmVersion:'shanghai',
outputSelection:{'*':{'*':['abi','evm.bytecode.object','evm.gasEstimates']}}}};
const out=JSON.parse(solc.compile(JSON.stringify(input)));
(out.errors||[]).forEach(e=>console.log(e.severity.toUpperCase()+': '+e.formattedMessage));
const c=out.contracts?.['ScanRegistry.sol']?.['ScanRegistry'];
if(!c){console.log('NO OUTPUT');process.exit(1);}
fs.mkdirSync('build',{recursive:true});
fs.writeFileSync('build/ScanRegistry.json',JSON.stringify({abi:c.abi,bytecode:'0x'+c.evm.bytecode.object},null,2));
console.log('OK solc',solc.version());
console.log('bytecode bytes:',c.evm.bytecode.object.length/2);
console.log('deploy gas:',c.evm.gasEstimates.creation.totalCost);
