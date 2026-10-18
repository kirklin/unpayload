package fixture;

@Tag(value = "triangle", weight = 4)
final class Triangle implements Shape {
    private final double base;
    private final double height;

    Triangle(double base, double height) {
        this.base = base;
        this.height = height;
    }

    @Override
    public double area() {
        return base * height / 2;
    }

    @Override
    public String name() {
        return "triangle";
    }
}
