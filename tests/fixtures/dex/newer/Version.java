package fixture;

final class Version {
    static final String NAME = "newer";
    static final long BUILD = 20261016L;

    static Shape extra(int i) {
        return new Triangle(i, i + 3);
    }

    static String label(Shape shape) {
        return NAME + "/" + BUILD + ":" + shape.name();
    }
}
