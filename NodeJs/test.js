#!/usr/bin/env node
const MiniAes = require('./utils/mini_aes')
const util = require('util')

let mini_aes_crypto = new MiniAes();
mini_aes_crypto.setkey("abcdefghijklmnopqrstuvwxyz");
let ecn_value = mini_aes_crypto.enc(0x0);
console.log('ecn_value: ', ecn_value.toString(16));
let dec_value = mini_aes_crypto.dec(ecn_value);
console.log('dec_value: ', dec_value.toString(16));
