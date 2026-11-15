'use strict';
function hx(ptr,n){ try{ var ab=ptr.readByteArray(n); if(!ab) return null; var b=new Uint8Array(ab),s=''; for(var i=0;i<n;i++){var h=b[i].toString(16); s+=(h.length<2?'0':'')+h;} return s; }catch(e){return null;} }
function u64(p){ try{ var v=p.readU64(); return (typeof v==='object'&&v.toNumber)?v.toNumber():v; }catch(e){return 0;} }
function L(mod){ try{return Process.findModuleByName(mod);}catch(e){return null;} }
function exp(mod,name){ var m=L(mod); try{return m?m.findExportByName(name):null;}catch(e){return null;} }
function cborish(b){ try{ if(!b||!b.byteLength) return false; var c=new Uint8Array(b)[0]; return (c>=0x80&&c<=0xbf);}catch(e){return false;} }
function emit(tag,buf,sz){ try{ if(!buf||buf.isNull()||sz<=0||sz>16384) return; var d=buf.readByteArray(sz); if(d&&d.byteLength) send({t:tag,size:sz},d); }catch(e){} }
function hookSer(name){ var p=exp('liboctbstack.so',name); if(!p){send({t:'info',msg:name+' MISSING'});return;}
  Interceptor.attach(p,{ onEnter:function(a){ try{this.pp=a[1];this.ps=a[2];}catch(e){this.pp=null;} },
    onLeave:function(){ try{ if(!this.pp)return; emit(name,this.pp.readPointer(),u64(this.ps)); }catch(e){} } });
  send({t:'info',msg:name+' hooked'}); }
function hookParse(name){ var p=exp('liboctbstack.so',name); if(!p){send({t:'info',msg:name+' MISSING'});return;}
  Interceptor.attach(p,{ onEnter:function(a){ try{ var sz=a[1].toInt32(); emit(name,a[0],sz); }catch(e){} } });
  send({t:'info',msg:name+' hooked'}); }
function hookDo(){ var p=exp('liboctbstack.so','OCDoResource'); if(!p){send({t:'info',msg:'OCDoResource MISSING'});return;}
  var M={1:'GET',2:'PUT',4:'POST',8:'DELETE',16:'OBSERVE',256:'DISCOVER'};
  Interceptor.attach(p,{ onEnter:function(a){ try{var m=a[1].toInt32();var uri=a[2].isNull()?'':a[2].readCString();send({t:'REQ',method:(M[m]||m),uri:uri});}catch(e){} } });
  send({t:'info',msg:'OCDoResource hooked'}); }
function hookConv(){ var p=exp('liboctbstack.so','OCConvertPayload'); if(!p){send({t:'info',msg:'OCConvertPayload MISSING'});return;}
  Interceptor.attach(p,{ onEnter:function(a){ this.a=[a[1],a[2],a[3]]; }, onLeave:function(){ try{ var cand=[[this.a[1],this.a[2]],[this.a[0],this.a[1]]];
    for(var i=0;i<cand.length;i++){ try{ var buf=cand[i][0].readPointer(); if(buf.isNull())continue; var sz=u64(cand[i][1]); if(sz<=0||sz>16384)continue; var d=buf.readByteArray(sz); if(cborish(d)){ send({t:'OCConvertPayload',size:sz},d); return; } }catch(e){} } }catch(e){} } });
  send({t:'info',msg:'OCConvertPayload hooked'}); }
function hookParseGen(){ var p=exp('liboctbstack.so','OCParsePayload'); if(!p){send({t:'info',msg:'OCParsePayload MISSING'});return;}
  Interceptor.attach(p,{ onEnter:function(a){ try{ var sz=a[4].toInt32(); if(sz>0&&sz<=16384){ var d=a[3].readByteArray(sz); if(cborish(d)) send({t:'OCParsePayload(in)',size:sz},d);} }catch(e){} } });
  send({t:'info',msg:'OCParsePayload hooked'}); }
function hookPsk(){ var p=exp('liboctbstack.so','CAGenerateOwnerPSK'); if(!p)return;
  Interceptor.attach(p,{ onEnter:function(a){ try{this.d=a[3];this.o=a[5];this.p=a[7];this.l=a[8].toInt32();}catch(e){} }, onLeave:function(){ try{send({t:'OWNERPSK',deviceuuid:hx(this.d,16),owneruuid:hx(this.o,16),psk:hx(this.p,this.l||16)});}catch(e){} } });
  send({t:'info',msg:'CAGenerateOwnerPSK hooked'}); }
var iv=setInterval(function(){ if(L('liboctbstack.so')){ clearInterval(iv);
  ['DoxmToCBORPayload','CredToCBORPayload','AclToCBORPayload','PstatToCBORPayload'].forEach(hookSer);
  ['CBORPayloadToDoxm','CBORPayloadToPstat','CBORPayloadToAcl','CBORPayloadToCred'].forEach(hookParse);
  hookDo(); hookConv(); hookParseGen(); hookPsk();
} },500);
