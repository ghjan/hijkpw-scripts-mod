const pinyin = require('tiny-pinyin')
var fs = require('fs');
path='v2ray_mod1.sh.txt';
var file = fs.readFileSync(path, "utf8");
console.log(file);

result=pinyin.convertToPinyin(file, '-', true) // wo-men-he-ta-men
console.log(result);
