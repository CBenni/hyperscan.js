const hyperscan = require('../hyperscan');

const db = hyperscan.hsCompile('Wo.*');
console.log(`Database info: ${hyperscan.hsDatabaseInfo(db)}`);
const data = 'Hello World!';
hyperscan.hsScanAsync(db, data, (id, from, to) => {
  const str = data.slice(from, to);
  console.log(`Match asynchronously found! id: ${id}, from: ${from}, to: ${to}, string: ${str}`);
}).then(result => {
  console.log(`hs_scan async result: ${result}`);
}).catch(err => {
  console.error('hs_scan async  error: ', err);
});

setTimeout(() => {}, 1000);
