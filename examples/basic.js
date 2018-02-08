import hyperscan from '../hyperscan'

var db = hyperscan.hsCompile("Wo.*");
console.log("Database info: "+hyperscan.hsDatabaseInfo(db));
var data = "Hello World!";
hyperscan.hsScan(db, data, function(id, from, to){
	if(id !== null) {
		var str = data.slice(from, to);
		console.log(`Match found! id: ${id}, from: ${from}, to: ${to}, string: ${str}`)
	} else {
		console.log("No match found.");
	}
})