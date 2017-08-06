#ifndef PLUGKIT_FRAME_VIEW_H
#define PLUGKIT_FRAME_VIEW_H

#include <memory>
#include <vector>
#include "export.h"
#include "token.h"

namespace plugkit {

class Frame;
class FrameView;
class Layer;
class Property;

class PLUGKIT_EXPORT FrameView final {
public:
  explicit FrameView(const Frame *frame);
  ~FrameView();
  const Frame *frame() const;
  const Layer *primaryLayer() const;
  const std::vector<const Layer *> &leafLayers() const;
  const Property *propertyFromId(Token id) const;
  const Layer *layerFromId(Token id) const;

private:
  class Private;
  std::unique_ptr<Private> d;
};
}

#endif