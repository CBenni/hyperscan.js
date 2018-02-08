const hyperscan = require('../hyperscan');

const db = hyperscan.hsCompile('Wo.*');
console.log(`Database info: ${hyperscan.hsDatabaseInfo(db)}`);
const data = 'Hello World!';
hyperscan.hsScan(db, data, (id, from, to) => {
  if (id !== null) {
    const str = data.slice(from, to);
    console.log(`Match found! id: ${id}, from: ${from}, to: ${to}, string: ${str}`);
  } else {
    console.log('No match found.');
  }
});
