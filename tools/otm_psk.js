'use strict';
function hexb(ptr, n){ try{ var ab=ptr.readByteArray(n); if(!ab) return '<null>'; var b=new Uint8Array(ab); var s=''; for(var i=0;i<n;i++){var h=b[i].toString(16); s+=(h.length<2?'0':'')+h;} return s; }catch(e){return '<err:'+e+'>';} }
function uuidStr(ptr){ var h=hexb(ptr,16); if(h.length<32) return h; return h.slice(0,8)+'-'+h.slice(8,12)+'-'+h.slice(12,16)+'-'+h.slice(16,20)+'-'+h.slice(20,32); }
function hook(){
  var m = Process.findModuleByName('liboctbstack.so');
  var p = m ? m.findExportByName('CAGenerateOwnerPSK') : null;
  if(!p){ send({t:'info',msg:'CAGenerateOwnerPSK not found pid '+Process.id}); return; }
  Interceptor.attach(p, {
    onEnter: function(a){ this.dev=a[3]; this.own=a[5]; this.psk=a[7]; this.pskLen=a[8].toInt32();
      this.label=''; try{ this.label=a[1].readCString(); }catch(e){} },
    onLeave: function(ret){ send({t:'OWNERPSK', ret: ret.toInt32(), label: this.label,
      deviceuuid: uuidStr(this.dev), owneruuid: uuidStr(this.own),
      psk: hexb(this.psk, this.pskLen||16)}); }
  });
  send({t:'info', msg:'CAGenerateOwnerPSK hooked @ '+p+' pid '+Process.id});
}
var tries=0; var iv=setInterval(function(){ tries++;
  if(Process.findModuleByName('liboctbstack.so')){ clearInterval(iv); hook(); }
  else if(tries>240){ clearInterval(iv); } },500);
