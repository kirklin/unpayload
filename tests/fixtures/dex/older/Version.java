package fixture;

final class Version {
    static final String NAME = "older";

    static Shape extra(int i) {
        return new Circle(i + 2);
    }

    static String label(Shape shape) {
        return NAME + ":" + shape.name();
    }
}
