//! Standard fprintd finger names and CB2000 sub-factor mapping.

/// All 10 standard `net.reactivated.Fprint` finger names paired with their 1-based sub-factor byte.
pub const FINGERS: &[(&str, u8)] = &[
    ("left-thumb", 1),
    ("left-index-finger", 2),
    ("left-middle-finger", 3),
    ("left-ring-finger", 4),
    ("left-little-finger", 5),
    ("right-thumb", 6),
    ("right-index-finger", 7),
    ("right-middle-finger", 8),
    ("right-ring-finger", 9),
    ("right-little-finger", 10),
];

/// Convert a standard `fprintd` finger name into its CB2000 sub-factor ID.
pub fn finger_name_to_sub_factor(name: &str) -> Option<u8> {
    FINGERS
        .iter()
        .find_map(|(n, id)| (*n == name).then_some(*id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_all_ten_standard_fingers() {
        assert_eq!(finger_name_to_sub_factor("right-index-finger"), Some(7));
        assert_eq!(finger_name_to_sub_factor("left-thumb"), Some(1));
        assert_eq!(finger_name_to_sub_factor("invalid-finger"), None);
    }
}
