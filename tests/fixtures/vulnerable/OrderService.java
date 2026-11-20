package com.example.demo;

import org.springframework.stereotype.Service;

// Vulnerable fixture: the service passes a method parameter straight to
// repo.save() with no validation or field filtering (R-06).
@Service
public class OrderService {

    private final OrderRepository orderRepository;

    public OrderService(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }

    public Order savesProduct(Order order) {
        return orderRepository.save(order);
    }

    // This IS an R-06 finding too: checking one field does not filter the rest.
    // Every other field the caller supplied is still persisted as-is.
    public Order saveAfterNullCheck(Order order) {
        if (order.getTotal() == null) {
            throw new IllegalArgumentException("total is required");
        }
        return orderRepository.save(order);
    }

    public void delete(int id) {
        orderRepository.deleteById(id);
    }
}
