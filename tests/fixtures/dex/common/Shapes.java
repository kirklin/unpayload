package fixture;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.function.DoubleUnaryOperator;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER})
@interface Tag {
    String value();

    int weight() default 1;
}

interface Shape {
    double area();

    String name();
}

@Tag("circle")
final class Circle implements Shape {
    @Tag(value = "radius", weight = 2)
    private final double radius;

    Circle(double radius) {
        this.radius = radius;
    }

    @Override
    @Tag("area")
    public double area() {
        return Math.PI * radius * radius;
    }

    @Override
    public String name() {
        return "circle";
    }
}

@Tag(value = "rectangle", weight = 3)
final class Rectangle implements Shape {
    private final double width;

    @Tag("height")
    private final double height;

    Rectangle(double width, double height) {
        this.width = width;
        this.height = height;
    }

    @Override
    public double area() {
        return width * height;
    }

    @Override
    public String name() {
        return "rectangle";
    }
}

public final class Shapes {
    static final String GREETING = "shapes";
    static final int[] PRIMES = {2, 3, 5, 7, 11, 13};
    static int counter;

    public static List<Shape> build(int count) {
        List<Shape> shapes = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            switch (i % 4) {
                case 0:
                    shapes.add(new Circle(i));
                    break;
                case 1:
                    shapes.add(new Rectangle(i, i + 1));
                    break;
                case 2:
                    shapes.add(Version.extra(i));
                    break;
                default:
                    shapes.add(new Circle(i * 0.5));
                    break;
            }
        }
        shapes.sort(Comparator.comparingDouble(Shape::area));
        return shapes;
    }

    public static String describe(@Tag("shape") Shape shape) {
        switch (shape.name()) {
            case "circle":
                return "round " + shape.area();
            case "rectangle":
                return "boxy " + shape.area();
            default:
                return Version.label(shape);
        }
    }

    public static double total(List<Shape> shapes, DoubleUnaryOperator scale) {
        double sum = 0;
        int[] weights = {3, 1, 4, 1, 5, 9, 2, 6};
        int index = 0;
        for (Shape shape : shapes) {
            try {
                sum += scale.applyAsDouble(shape.area()) * weights[index++ % weights.length];
                counter += 1000 / (index - 3);
            } catch (ArithmeticException e) {
                counter = -1;
            } finally {
                counter++;
            }
        }
        return sum;
    }

    public static double measure(Shape shape) throws Throwable {
        MethodHandle area = MethodHandles.lookup()
                .findVirtual(Shape.class, "area", MethodType.methodType(double.class));
        return (double) area.invokeExact(shape);
    }
}
