use std::ops::Mul;

/// Multiplier efficiently computes the product of all values except one.
///
/// The multiplier constructs a tree where leaf nodes represent given values,
/// and internal nodes represent the product of their children's values.
/// To obtain the product of all values except one, traverse down the tree
/// to the node containing that value and multiply the values of sibling nodes
/// encountered along the way.
pub struct Multiplier<T>
where
    T: Mul<Output = T> + Clone + Default,
{
    /// The root node of the tree.
    root: Node<T>,
}

impl<T> Multiplier<T>
where
    T: Mul<Output = T> + Clone + Default,
{
    /// Constructs a new multiplier using the given values.
    pub fn new(values: &[T]) -> Self {
        let root = Self::create(values, true);

        Self { root }
    }

    /// Helper function to recursively construct the tree.
    fn create(values: &[T], root: bool) -> Node<T> {
        match values.len() {
            0 => {
                // When given an empty slice, return zero, which should be the default value.
                return Node::Leaf(LeafNode {
                    value: Default::default(),
                });
            }
            1 => {
                // Store values in the leaf nodes.
                return Node::Leaf(LeafNode {
                    value: values[0].clone(),
                });
            }
            _ => (),
        }

        let size = values.len();
        let middle = size / 2;
        let left = Box::new(Self::create(&values[..middle], false));
        let right = Box::new(Self::create(&values[middle..], false));
        let value = match root {
            true => None,
            false => Some(left.get_value() * right.get_value()),
        };

        Node::Internal(InternalNode {
            value,
            left,
            right,
            size,
        })
    }

    /// Returns the product of all values except the one at the given index.
    pub fn get_product(&self, index: usize) -> T {
        self.root.get_product(index).unwrap_or_default()
    }
}

/// Represents a node in the tree.
enum Node<T> {
    /// Internal nodes store the product of their children's values.
    Internal(InternalNode<T>),
    /// Leaf nodes store given values.
    Leaf(LeafNode<T>),
}

impl<T> Node<T>
where
    T: Mul<Output = T> + Clone,
{
    /// Returns the value stored in the node.
    ///
    /// # Panics
    ///
    /// This function panics if called on the root node.
    fn get_value(&self) -> T {
        match self {
            Node::Internal(n) => n.value.clone().expect("should not be called on root node"),
            Node::Leaf(n) => n.value.clone(),
        }
    }

    /// Returns the number of leaf nodes in the subtree.
    fn get_size(&self) -> usize {
        match self {
            Node::Internal(n) => n.size,
            Node::Leaf(_) => 1,
        }
    }

    /// Returns the product of all values stored in the subtree except
    /// the one at the given index.
    fn get_product(&self, index: usize) -> Option<T> {
        match self {
            Node::Internal(n) => {
                let left_size = n.left.get_size();
                match index < left_size {
                    true => {
                        if let Some(value) = n.left.get_product(index) {
                            Some(n.right.get_value() * value)
                        } else {
                            Some(n.right.get_value())
                        }
                    }
                    false => {
                        if let Some(value) = n.right.get_product(index - left_size) {
                            Some(n.left.get_value() * value)
                        } else {
                            Some(n.left.get_value())
                        }
                    }
                }
            }
            Node::Leaf(n) => {
                if index > 0 {
                    Some(n.value.clone())
                } else {
                    None
                }
            }
        }
    }
}

/// Represents an internal node in the tree.
struct InternalNode<T> {
    /// The product of its children's values.
    ///
    /// Optional for the root node.
    value: Option<T>,
    /// The left child node.
    left: Box<Node<T>>,
    /// The right child node.
    right: Box<Node<T>>,
    /// The number of leaf nodes in the subtree.
    size: usize,
}

/// Represents a leaf node in the tree.
struct LeafNode<T> {
    /// The value stored in the leaf node.
    value: T,
}

#[cfg(test)]
mod tests {
    use super::Multiplier;

    #[test]
    fn test_multiplier() {
        // No values.
        let m = Multiplier::<usize>::new(&vec![]);
        for i in 0..10 {
            let product = m.get_product(i);
            assert_eq!(product, 0);
        }

        // One value.
        let values = vec![1];
        let products = vec![0, 1, 1];
        let m = Multiplier::new(&values);

        for (i, expected) in products.into_iter().enumerate() {
            let product = m.get_product(i);
            assert_eq!(product, expected);
        }

        // Many values.
        let values = vec![1, 2, 3, 4, 5];
        let total = values.iter().fold(1, |acc, x| acc * x);
        let products = values.iter().map(|x| total / x);
        let m = Multiplier::new(&values);

        for (i, expected) in products.enumerate() {
            let product = m.get_product(i);
            assert_eq!(product, expected);
        }

        // Index out of bounds.
        for i in 5..10 {
            let product = m.get_product(i);
            assert_eq!(product, total);
        }
    }
}
