package wtf.imba.ultimaterootchecker;

import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;


public class InfoFragment extends Fragment {

    public static InfoFragment newInstance() {
        return new InfoFragment();
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        View rootView = inflater.inflate(R.layout.fragment_info, container, false);
        TextView textView = (TextView) rootView.findViewById(R.id.section_label);
        return rootView;
    }

}
