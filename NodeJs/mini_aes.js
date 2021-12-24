class MiniAes {

    #round = 8;
    #max_key_len = this.#round * 4;
    #key_array;

    constructor() {
        this.key = null;
    }

    setkey(key) {
        if (typeof key !== 'string')
        {
            key = String(key);
        }

        let fil_len = this.#max_key_len - 1;
        let key_len = key.length > fil_len? fil_len: key.length;
        let pad_len = fil_len - key_len;

        if (fil_len <= key_len) {
            key = key.substring(0, fil_len);
            pad_len = 0;
        }

        let key_array = [];

        key_array.push(...Buffer.from(key));
        if (pad_len > 0) {
            for (let i=0; i<pad_len; i++) {
                key_array.push(pad_len);
            }
        }
        key_array.push(key_len);

        this.#key_array = key_array;
    } 

    #runEnc(a, b, c, d, k)
    {
        /* xor */
        a ^= k[0];
        b ^= k[1];
        c ^= k[2];
        d ^= k[3];

        /* mix */
        let e = a;
        let f = b;
        let g = c;
        let h = d;

        a = ((e & 0xC0) | (f & 0x30) | (g & 0x0C) | (h & 0x03)) & 0xFF;
        b = ((f & 0xC0) | (g & 0x30) | (h & 0x0C) | (e & 0x03)) & 0xFF;
        c = ((g & 0xC0) | (h & 0x30) | (e & 0x0C) | (f & 0x03)) & 0xFF;
        d = ((h & 0xC0) | (e & 0x30) | (f & 0x0C) | (g & 0x03)) & 0xFF;

        e = f = g = h = 0;

        /* s-box */
        a = (((a) << 4) + ((a) << 3) + ((a) << 1) + (a)) & 0xFF;
        b = (((b) << 4) + ((b) << 3) + ((b) << 1) + (b)) & 0xFF;
        c = (((c) << 4) + ((c) << 3) + ((c) << 1) + (c)) & 0xFF;
        d = (((d) << 4) + ((d) << 3) + ((d) << 1) + (d)) & 0xFF;

        return [a, b, c, d];
    }

    enc(input) {
        if (typeof input !== 'number') {
            input = parseInt(input);
        }

        let a = (input & 0xFF000000) >> 24;
        let b = (input & 0x00FF0000) >> 16;
        let c = (input & 0x0000FF00) >>  8;
        let d = (input & 0x000000FF)      ;

        for (let i=0; i<this.#round; i++) {
            let k = this.#key_array.slice(i*4, (i+1)*4);
            let round_ret = this.#runEnc(a, b, c, d, k);
            a = round_ret[0]; b = round_ret[1]; c = round_ret[2]; d = round_ret[3];
        }

        input = a*0x1000000 + b*0x10000 + c*0x100 + d;

        return input;
    }

    #runDec(a, b, c, d, k)
    {
        /* s-box */
        a = (((a) << 4) + ((a) << 1) + (a)) & 0xFF;
        b = (((b) << 4) + ((b) << 1) + (b)) & 0xFF;
        c = (((c) << 4) + ((c) << 1) + (c)) & 0xFF;
        d = (((d) << 4) + ((d) << 1) + (d)) & 0xFF;

        /* mix */
        let e = a;
        let f = b;
        let g = c;
        let h = d;

        a = ((e & 0xC0) | (h & 0x30) | (g & 0x0C) | (f & 0x03)) & 0xFF;
        b = ((f & 0xC0) | (e & 0x30) | (h & 0x0C) | (g & 0x03)) & 0xFF;
        c = ((g & 0xC0) | (f & 0x30) | (e & 0x0C) | (h & 0x03)) & 0xFF;
        d = ((h & 0xC0) | (g & 0x30) | (f & 0x0C) | (e & 0x03)) & 0xFF;

        e = f = g = h = 0;

        /* xor */
        a ^= k[0];
        b ^= k[1];
        c ^= k[2];
        d ^= k[3];

        return [a, b, c, d];
    }

    dec(input) {
        if (typeof input !== 'number') {
            input = parseInt(input);
        }

        let a = (input & 0xFF000000) >> 24;
        let b = (input & 0x00FF0000) >> 16;
        let c = (input & 0x0000FF00) >>  8;
        let d = (input & 0x000000FF)      ;

        for (let i=this.#round-1; i>=0; i--) {
            let k = this.#key_array.slice(i*4, (i+1)*4);
            let round_ret = this.#runDec(a, b, c, d, k);
            a = round_ret[0]; b = round_ret[1]; c = round_ret[2]; d = round_ret[3];
        }

        input = a*0x1000000 + b*0x10000 + c*0x100 + d;

        return input;
    }
}

module.exports = MiniAes
