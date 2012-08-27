
function init_welcome() {
  ELE("open-generate").onclick =  function() {
    sections.open("genkey"); 
  }
  ELE("open-import").onclick =  function() {
    sections.open("import"); 
  }
}
