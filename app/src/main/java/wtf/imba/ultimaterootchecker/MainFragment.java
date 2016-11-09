package wtf.imba.ultimaterootchecker;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Color;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.v4.app.ListFragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.TextView;

import java.util.Arrays;
import java.util.List;


public class MainFragment extends ListFragment {

    private List<String> names = Arrays.asList(
            "su Managers",
            "su Binary",
            "busybox Binary",
            "dangerous Build.prop values",
            "rw System Folders",
            "test-keys",
            "check Su Exists",
            "detect Root Hiders",
            "Xposed or Cydia"
    );


    public static MainFragment newInstance() {
        return new MainFragment();
    }

    @Nullable
    @Override
    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_main, container, false);
    }

    @Override
    public void onActivityCreated(@Nullable Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
        setListAdapter(new CheckArrayAdapter(getActivity(), R.layout.list_cell, names));
    }

    class CheckArrayAdapter extends ArrayAdapter<String> implements View.OnClickListener{
        private Context context;
        private int resource;
        private List<String> objects;
        private RootChecker rootChecker;
        private boolean rootState = false;

        CheckArrayAdapter(Context context, int resource, List<String> objects) {
            super(context, resource, objects);
            this.context = context;
            this.resource = resource;
            this.objects = objects;
            rootChecker = new RootChecker(context);
        }

        @Override
        public String getItem(int position) {
            return objects.get(position);
        }

        @NonNull
        @Override
        public View getView(int position, View convertView, @NonNull ViewGroup parent) {
            TextView cellText = (TextView)convertView;
            if (cellText == null) {
                cellText = (TextView) LayoutInflater.from(context).inflate(resource, parent, false);
                cellText.setOnClickListener(this);
            }
            cellText.setText(getItem(position));

            if (rootChecker.check(getItem(position))) {
                cellText.setBackgroundColor(Color.RED);
                rootState = true;
            } else {
                cellText.setBackgroundColor(Color.GREEN);
            }
            if (position == objects.size() - 1) {
                showAlert(rootState);
            }
            return cellText;
        }

        private void showAlert(boolean state) {
            AlertDialog.Builder builder = new AlertDialog.Builder(getActivity());
            builder.setTitle(getActivity().getString(R.string.app_name)).setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {

                }
            }).setIcon(android.R.drawable.ic_dialog_alert);
            if (state) {
                builder.setMessage("Your device ROOTED");
            } else {
                builder.setMessage("Your device NOT ROOTED");
            }
            builder.show();
        }

        @Override
        public void onClick(View view) {
            String reason = rootChecker.getRootReason(((TextView)view).getText().toString());
            if (reason == null) {
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(getActivity());
            builder.setTitle(((TextView)view).getText().toString()).setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {

                }
            }).setIcon(android.R.drawable.ic_dialog_alert);
            builder.setMessage(reason);
            builder.show();
        }
    }
}
