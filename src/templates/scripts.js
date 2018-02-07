function addMoreHeaders(el) {
  var parent = el.parentElement,
      grandParent = parent.parentElement,
      cloned = parent.cloneNode(true),
      sibling = parent.nextSibling;

  cloned.querySelectorAll('input[type="text"]').forEach(function (item) {
      item.value = '';
  });

  grandParent.insertBefore(cloned, sibling);
  parent.removeChild(el);
}

function deleteRule(source) {
  return confirm('Do you really want to delete the rule for ' + source + ' ?');
}
