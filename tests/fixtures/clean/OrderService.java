package com.example.demo;

import org.springframework.stereotype.Service;

// Clean fixture: the service builds the entity itself from a request object
// (only safe fields are copied) and saves the locally built object, not the
// parameter. No R-06 finding expected.
@Service
public class OrderService {

    private final OrderRepository orderRepository;

    public OrderService(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }

    public Order createOrder(OrderRequest request) {
        Order order = new Order();
        order.setName(request.getName());
        return orderRepository.save(order);
    }

    // Also clean: only an allowlist of fields is copied from the caller's
    // object onto an entity loaded from the database, and that entity is
    // what gets saved — the caller's object never reaches the repository.
    public void saveChanges(String name, OrderRequest update) {
        Order order = orderRepository.findByName(name);
        order.setTotal(update.getTotal());
        order.setNote(update.getNote());
        orderRepository.save(order);
    }
}
