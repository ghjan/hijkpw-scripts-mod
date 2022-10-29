// test.js
const pinyin = require('tiny-pinyin')

if (pinyin.isSupported()) {
    result=pinyin.convertToPinyin('我') // WO
    console.log(result)
    result=pinyin.convertToPinyin('我们和他们', '-', true) // wo-men-he-ta-men
    console.log(result)
}