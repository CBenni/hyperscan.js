import hyperscan from '../hyperscan'

var db = hyperscan.hsCompile("Wo.*");
console.log("Database info: "+hyperscan.hsDatabaseInfo(db));
var data = "Hello World!";
hyperscan.hsScanAsync(db, data, function(id, from, to){
	var str = data.slice(from, to);
	console.log(`Match asynchronously found! id: ${id}, from: ${from}, to: ${to}, string: ${str}`)
}).then(function(result){
	console.log("hs_scan async result: "+result);
}).catch(err => {
	console.error("hs_scan async  error: ", err);
});

setTimeout(()=>{},1000);