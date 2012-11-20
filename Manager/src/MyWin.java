import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * User: paulo
 * Date: 11/20/12
 * Time: 10:05 AM
 */
public class MyWin extends JFrame
{
    private ConsoleListener ml;
    private JTextField line;


    public MyWin()
    {
        super("Console");
        Container c = getContentPane();
        c.setLayout(new FlowLayout());

        line = new JTextField(60);
        line.setEditable(true);
        c.add(line);

        ml = new ConsoleListener();
        line.addActionListener(ml);

        setSize(800,80);
        setLocation(100,0);
        setVisible(true);
    }

    private class ConsoleListener  implements ActionListener
    {
        private String l;

        public void actionPerformed(ActionEvent e) {
            l = e.getActionCommand();

        }

    }

}
