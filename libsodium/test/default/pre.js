try {
    this['Module'] = Module;
    Module.test;
} catch(e) {
    this['Module'] = Module = {};
}
Module['preRun'] = Module['preRun'] || [];
Module['preRun'].push(function(){
    var randombyte = null;    
    try {
        function randombyte_standard() {
            var buf = new Int8Array(1);            
            window.crypto.getRandomValues(buf);
            return buf[0];
        }
        randombyte_standard();
        randombyte = randombyte_standard;
    } catch (e) {
        try {
            var crypto = require('crypto');
            function randombyte_node() {
                return crypto.randomBytes(1)[0];
            }
            randombyte_node();
            randombyte = randombyte_node;
        } catch(e) { }
    }
    FS.init();
    var devFolder = FS.findObject('/dev') ||
        Module['FS_createFolder']('/', 'dev', true, true);    
    Module['FS_createDevice'](devFolder, 'random', randombyte);
    Module['FS_createDevice'](devFolder, 'urandom', randombyte);    
});
