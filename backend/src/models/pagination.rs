//! Pagination and filtering primitives shared across all list endpoints.

use serde::{Deserialize, Serialize};

/// Pagination query parameters.
#[derive(Debug, Clone, Deserialize)]
pub struct Pagination {
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

impl Pagination {
    /// Maximum items per page.
    const MAX_PER_PAGE: i64 = 100;

    /// Default items per page.
    const DEFAULT_PER_PAGE: i64 = 25;

    pub fn limit(&self) -> i64 {
        self.per_page
            .unwrap_or(Self::DEFAULT_PER_PAGE)
            .clamp(1, Self::MAX_PER_PAGE)
    }

    pub fn offset(&self) -> i64 {
        let page = self.page.unwrap_or(1).max(1);
        (page - 1) * self.limit()
    }

    pub fn current_page(&self) -> i64 {
        self.page.unwrap_or(1).max(1)
    }
}

/// Paged result envelope returned by list endpoints.
#[derive(Debug, Clone, Serialize)]
pub struct PagedResult<T: Serialize> {
    pub items: Vec<T>,
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
    pub total_pages: i64,
}

impl<T: Serialize> PagedResult<T> {
    pub fn new(items: Vec<T>, total: i64, pagination: &Pagination) -> Self {
        let per_page = pagination.limit();
        let total_pages = (total + per_page - 1) / per_page;
        Self {
            items,
            total,
            page: pagination.current_page(),
            per_page,
            total_pages,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pagination_defaults() {
        let p = Pagination {
            page: None,
            per_page: None,
        };
        assert_eq!(p.limit(), 25);
        assert_eq!(p.offset(), 0);
        assert_eq!(p.current_page(), 1);
    }

    #[test]
    fn pagination_clamps_per_page() {
        let p = Pagination {
            page: Some(1),
            per_page: Some(500),
        };
        assert_eq!(p.limit(), 100);
    }

    #[test]
    fn pagination_offset_calculation() {
        let p = Pagination {
            page: Some(3),
            per_page: Some(10),
        };
        assert_eq!(p.offset(), 20);
    }

    #[test]
    fn paged_result_total_pages() {
        let p = Pagination {
            page: Some(1),
            per_page: Some(10),
        };
        let result = PagedResult::new(vec![1, 2, 3], 25, &p);
        assert_eq!(result.total_pages, 3);
        assert_eq!(result.total, 25);
        assert_eq!(result.page, 1);
    }
}
