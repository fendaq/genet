const m = require('mithril')
class Enum {
  view (vnode) {
    const { value } = vnode.attrs.prop
    const flags = vnode.attrs.layer.attrs
      .filter((prop) => prop.id.startsWith(`${vnode.attrs.prop.id}.`))
      .map((prop) => {
        const { id } = prop
        return deplug.session.token(id).name
    })
    .join(', ')
    return m('span', [flags, ' (', value, ')'])
  }
}
module.exports = Enum